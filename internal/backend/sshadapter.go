// Copyright 2026 Dunkel Cloud GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/sshcmd"
)

// TransportSSH is the transport of a backends.yaml entry whose tools are
// commands run on hosts over SSH.
const TransportSSH = transportTypeSSH

// sshHealthTimeout bounds the health check of one host.
const sshHealthTimeout = 15 * time.Second

// invalidUTF8 stands in a result for bytes of the output that are no UTF-8:
// the Unicode replacement character.
const invalidUTF8 = string(rune(0xFFFD))

// SSHConfig is the ssh block of a backends.yaml entry of transport ssh: how
// ToolMesh reaches the hosts the entry's commands run on.
type SSHConfig struct {
	// User is the account on the hosts.
	User string `yaml:"user"`
	// Hosts are the hosts of the backend, each written as "host" or
	// "host:port". With one host every command runs there; with several, a
	// call names one of them in the parameter "host".
	Hosts []string `yaml:"hosts"`
	// KnownHosts is the path of a file in OpenSSH known_hosts format with
	// the key of every host. A host whose key is not in it is not
	// connected to; the check cannot be turned off.
	KnownHosts string `yaml:"known_hosts"`
	// KeyCredential names the credential that holds the private key
	// (CREDENTIAL_<NAME> in the credential store): the key in PEM form, the
	// same with \n for every line break, or the whole of it in base64.
	KeyCredential string `yaml:"key_credential"`
	// KeyFile is the path of a private key file, instead of KeyCredential.
	KeyFile string `yaml:"key_file"`
	// PassphraseCredential names the credential that holds the passphrase
	// of the private key, for a key that is protected by one.
	PassphraseCredential string `yaml:"passphrase_credential"`
}

// SSHAdapterOptions configures an SSHAdapter.
type SSHAdapterOptions struct {
	// Name is the backend's name, the name of its backends.yaml entry.
	Name string
	// SSH holds the connection settings, with paths ready to open.
	SSH SSHConfig
	// Hint is the operator's guidance for this backend.
	Hint string
	// HintRequiredFor lists the access classes whose commands run only for
	// a caller that shows it has received Hint.
	HintRequiredFor []string
	// IncludeTools, when set, lists the only commands the backend offers.
	IncludeTools []string
}

// SSHAdapter runs the commands of a command file on hosts reached over SSH.
// Each command is a tool; a call fills in the parameters of its template
// and gets back what the command wrote and how it ended.
//
// The adapter keeps no connection: every call connects, logs in with the
// backend's key, runs one command without a terminal and disconnects.
type SSHAdapter struct {
	name   string
	spec   *sshcmd.Spec
	creds  credentials.CredentialStore
	logger *slog.Logger

	user                 string
	hosts                []sshHost
	knownHosts           string
	keyCredential        string
	keyFile              string
	passphraseCredential string

	hint            string
	hintRequiredFor []string
	// include is the include_tools allow-set; nil offers every command.
	include map[string]bool
	// hostParam declares the parameter "host"; nil for a single host.
	hostParam map[string]dadl.ParamDef

	key  keyCache
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewSSHAdapter creates the backend for a command file and the connection
// settings of a backends.yaml entry. It checks the settings and connects to
// nothing: a host that is down or a key that is missing shows in the health
// check and fails the calls, not the load.
func NewSSHAdapter(spec *sshcmd.Spec, creds credentials.CredentialStore, logger *slog.Logger, opts SSHAdapterOptions) (*SSHAdapter, error) {
	if spec == nil {
		return nil, errors.New("no command file")
	}
	if opts.Name == "" {
		return nil, errors.New("the backend has no name")
	}
	cfg := opts.SSH
	user := strings.TrimSpace(cfg.User)
	if err := checkSSHUser(user); err != nil {
		return nil, err
	}
	if len(cfg.Hosts) == 0 {
		return nil, errors.New("ssh.hosts is empty: name the host or hosts the commands run on")
	}
	hosts := make([]sshHost, 0, len(cfg.Hosts))
	seen := make(map[string]bool, len(cfg.Hosts))
	for _, h := range cfg.Hosts {
		host, err := parseSSHHost(h)
		if err != nil {
			return nil, fmt.Errorf("ssh.hosts: %w", err)
		}
		if seen[host.addr] {
			return nil, fmt.Errorf("ssh.hosts lists %s twice", host.name)
		}
		seen[host.addr] = true
		hosts = append(hosts, host)
	}
	if strings.TrimSpace(cfg.KnownHosts) == "" {
		return nil, errors.New("ssh.known_hosts is missing: the keys of the hosts must be known before anything is sent to them")
	}
	keyCredential, keyFile := strings.TrimSpace(cfg.KeyCredential), strings.TrimSpace(cfg.KeyFile)
	if (keyCredential == "") == (keyFile == "") {
		return nil, errors.New("set exactly one of ssh.key_credential and ssh.key_file")
	}

	a := &SSHAdapter{
		name:                 opts.Name,
		spec:                 spec,
		creds:                creds,
		logger:               logger,
		user:                 user,
		hosts:                hosts,
		knownHosts:           strings.TrimSpace(cfg.KnownHosts),
		keyCredential:        keyCredential,
		keyFile:              keyFile,
		passphraseCredential: strings.TrimSpace(cfg.PassphraseCredential),
		hint:                 opts.Hint,
		hintRequiredFor:      opts.HintRequiredFor,
		dial:                 (&net.Dialer{}).DialContext,
	}
	if len(opts.IncludeTools) > 0 {
		a.include = make(map[string]bool, len(opts.IncludeTools))
		for _, name := range opts.IncludeTools {
			if _, ok := spec.Tools[name]; !ok {
				logger.Warn("include_tools entry does not match any command, skipping", "backend", opts.Name, "tool", name)
				continue
			}
			a.include[name] = true
		}
	}
	if len(hosts) > 1 {
		a.hostParam = map[string]dadl.ParamDef{
			sshcmd.HostParam: {Type: schemaTypeString, Required: true, Description: "The host to run the command on."},
		}
	}
	return a, nil
}

// checkSSHUser refuses a user name that is empty or cannot be one.
func checkSSHUser(user string) error {
	if user == "" {
		return errors.New("ssh.user is missing: name the account on the hosts")
	}
	if strings.HasPrefix(user, "-") || strings.ContainsFunc(user, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || r == '@' || r == ':'
	}) {
		return fmt.Errorf("ssh.user %q is not an account name", user)
	}
	return nil
}

// Name returns the backend's name.
func (a *SSHAdapter) Name() string { return a.name }

// HostNames returns the hosts of the backend as the entry writes them.
func (a *SSHAdapter) HostNames() []string {
	names := make([]string, len(a.hosts))
	for i, h := range a.hosts {
		names[i] = h.name
	}
	return names
}

// ToolCount returns the number of commands the backend offers.
func (a *SSHAdapter) ToolCount() int {
	n := 0
	for name := range a.spec.Tools {
		if a.included(name) {
			n++
		}
	}
	return n
}

// included reports whether the backend offers the command.
func (a *SSHAdapter) included(name string) bool {
	return a.include == nil || a.include[name]
}

// tool returns the command of that name, when the backend offers it.
func (a *SSHAdapter) tool(name string) (*sshcmd.Tool, bool) {
	t, ok := a.spec.Tools[name]
	if !ok || !a.included(name) {
		return nil, false
	}
	return t, true
}

// descriptor describes a command as a tool.
func (a *SSHAdapter) descriptor(t *sshcmd.Tool) ToolDescriptor {
	schema := t.InputSchema()
	desc := t.Doc()
	if a.hostParam != nil {
		names := a.HostNames()
		values := make([]any, len(names))
		for i, n := range names {
			values[i] = n
		}
		props, _ := schema[schemaKeyProperties].(map[string]any)
		props[sshcmd.HostParam] = map[string]any{
			schemaKeyType:        schemaTypeString,
			schemaKeyDescription: a.hostParam[sshcmd.HostParam].Description,
			"enum":               values,
		}
		required, _ := schema[schemaKeyRequired].([]string)
		required = append(required, sshcmd.HostParam)
		sort.Strings(required)
		schema[schemaKeyRequired] = required
		desc += " The parameter host selects the host: one of " + strings.Join(names, ", ") + "."
	}
	return ToolDescriptor{
		Name:        t.Name,
		Description: desc,
		InputSchema: schema,
		Backend:     transportTypeSSH + ":" + a.name,
		Access:      t.Access,
	}
}

// ListTools returns the commands of the backend as tools.
func (a *SSHAdapter) ListTools(_ context.Context) ([]ToolDescriptor, error) {
	tools := make([]ToolDescriptor, 0, len(a.spec.Tools))
	for name, t := range a.spec.Tools {
		if a.included(name) {
			tools = append(tools, a.descriptor(t))
		}
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools, nil
}

// LookupTool implements ToolMetadataLookup.
func (a *SSHAdapter) LookupTool(toolName string) (ToolDescriptor, bool) {
	t, ok := a.tool(toolName)
	if !ok {
		return ToolDescriptor{}, false
	}
	return a.descriptor(t), true
}

// BackendSummaries implements BackendSummarizer. Entries that share a
// command file share a SpecID, so the catalog lists them in one line.
func (a *SSHAdapter) BackendSummaries() []BackendInfo {
	desc := a.spec.Description
	if desc == "" {
		desc = "Runs predefined commands on a host over SSH."
	}
	specID := a.spec.ContentHash
	if a.hostParam != nil {
		// These tools take one parameter more.
		specID += "+hosts"
	}
	return []BackendInfo{{
		Name:            a.name,
		Description:     desc,
		Hint:            a.hint,
		HintRequiredFor: a.hintRequiredFor,
		SpecID:          specID,
	}}
}

// ValidateToolParams implements ParamValidator: it checks the arguments of
// a call against the command's parameters and their limits and returns them
// with defaults filled in, so that a gate policy sees the values the command
// line is built from.
func (a *SSHAdapter) ValidateToolParams(toolName string, params map[string]any) (map[string]any, error) {
	t, ok := a.tool(toolName)
	if !ok {
		return params, nil
	}
	checked, _, err := a.check(t, params)
	return checked, err
}

// check validates the arguments of a call and selects its host.
func (a *SSHAdapter) check(t *sshcmd.Tool, params map[string]any) (map[string]any, sshHost, error) {
	checked, err := t.Check(params, a.hostParam)
	if err != nil {
		return nil, sshHost{}, err
	}
	if a.hostParam == nil {
		return checked, a.hosts[0], nil
	}
	name, _ := checked[sshcmd.HostParam].(string)
	for _, h := range a.hosts {
		if h.name == name {
			return checked, h, nil
		}
	}
	return nil, sshHost{}, &sshcmd.ValueError{
		Tool:    t.Name,
		Param:   sshcmd.HostParam,
		Problem: "must be one of: " + strings.Join(a.HostNames(), ", "),
	}
}

// Execute runs a command on its host and returns what it wrote and how it
// ended. A command that ends with an exit code its template does not count
// as success comes back as an error result with the same content.
//
// A host that cannot be reached, a login that is refused and a host key
// that is not the known one are failures of the backend: the call returns
// an error and nothing was run.
func (a *SSHAdapter) Execute(ctx context.Context, toolName string, params map[string]any) (*ToolResult, error) {
	t, ok := a.tool(toolName)
	if !ok {
		return nil, fmt.Errorf("tool %q not found in SSH backend %q", toolName, a.name)
	}
	checked, host, err := a.check(t, params)
	if err != nil {
		a.logger.WarnContext(ctx, "tool call rejected: arguments do not fit the command's parameters",
			"backend", a.name, "tool", toolName, "error", err)
		return errorToolResult(err), nil
	}
	line, err := t.Command(checked)
	if err != nil {
		return errorToolResult(err), nil
	}

	a.logger.InfoContext(ctx, "executing SSH command", "backend", a.name, "tool", toolName, "host", host.name)
	a.logger.DebugContext(ctx, "SSH command line", "backend", a.name, "tool", toolName, "command", line)

	run, err := a.run(ctx, host, line, t.Timeout, t.MaxOutput)
	if err != nil {
		// The caller gets the short form; what an operator needs to fix
		// the backend goes into the log.
		var connErr *sshConnectError
		if errors.As(err, &connErr) && !errors.Is(err, context.Canceled) {
			a.logger.ErrorContext(ctx, "SSH backend cannot connect; the command was not run",
				"backend", a.name, "tool", toolName, "host", host.name, "reason", connErr.reason, "error", connErr.detail)
		}
		return nil, fmt.Errorf("execute SSH tool %q: %w", toolName, err)
	}
	a.logger.InfoContext(ctx, "SSH command finished",
		"backend", a.name, "tool", toolName, "host", host.name,
		"exitCode", run.exitCode, "timedOut", run.timedOut, "durationMs", run.duration.Milliseconds())
	return a.result(t, host, line, run), nil
}

// sshResult is what a call returns: the command as it was sent, what it
// wrote and how it ended.
type sshResult struct {
	Host    string `json:"host"`
	Command string `json:"command"`
	// ExitCode is absent when the command did not end in time.
	ExitCode        *int   `json:"exit_code,omitempty"`
	Signal          string `json:"signal,omitempty"`
	TimedOut        bool   `json:"timed_out,omitempty"`
	Error           string `json:"error,omitempty"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	DurationMs      int64  `json:"duration_ms"`
}

// result renders the outcome of a run.
func (a *SSHAdapter) result(t *sshcmd.Tool, host sshHost, line string, run *sshRun) *ToolResult {
	out := sshResult{
		Host:            host.name,
		Command:         line,
		Signal:          run.signal,
		TimedOut:        run.timedOut,
		Stdout:          strings.ToValidUTF8(string(run.stdout), invalidUTF8),
		Stderr:          strings.ToValidUTF8(string(run.stderr), invalidUTF8),
		StdoutTruncated: run.stdoutTruncated,
		StderrTruncated: run.stderrTruncated,
		DurationMs:      run.duration.Milliseconds(),
	}
	meta := map[string]any{
		metadataKeyBackend:   a.name,
		metadataKeyTransport: transportTypeSSH,
	}
	failed := true
	if run.timedOut {
		out.Error = fmt.Sprintf("the command did not end within %s. Its connection was closed; the command may still be running on the host", t.Timeout)
		meta[metadataKeyErrorCode] = dadl.ErrCodeTimeout
	} else {
		code := run.exitCode
		out.ExitCode = &code
		meta[metadataKeyExitCode] = code
		failed = run.signal != "" || !t.Succeeded(code)
	}
	text, err := json.Marshal(out)
	if err != nil {
		return errorToolResult(fmt.Errorf("render the result: %w", err))
	}
	return &ToolResult{
		Content:  []any{textContent(string(text))},
		IsError:  failed,
		Metadata: meta,
	}
}

// Healthy implements ToolBackend: every host accepts the backend's login.
func (a *SSHAdapter) Healthy(ctx context.Context) error {
	if res := a.CheckHealth(ctx); !res.OK {
		return errors.New(res.Error)
	}
	return nil
}

// HasHealthCheck implements HealthChecker. An SSH backend always has a
// check: connecting and logging in.
func (a *SSHAdapter) HasHealthCheck() bool { return true }

// CheckHealth implements HealthChecker: it connects to every host and logs
// in, without running a command. A key that no longer opens a host, a host
// key that changed and a host that is down show here before a caller needs
// the backend.
func (a *SSHAdapter) CheckHealth(ctx context.Context) HealthResult {
	res := HealthResult{CheckedAt: time.Now()}
	var failures []string
	for _, host := range a.hosts {
		hostCtx, cancel := context.WithTimeout(ctx, sshHealthTimeout)
		client, err := a.connect(hostCtx, host)
		cancel()
		if err != nil {
			failures = append(failures, err.Error())
			code, reason := HealthErrProtocol, HealthErrProtocol
			var connErr *sshConnectError
			if errors.As(err, &connErr) {
				code, reason = connErr.code, connErr.reason
				a.logger.WarnContext(ctx, "SSH health check failed",
					"backend", a.name, "host", host.name, "reason", reason, "error", connErr.detail)
			}
			if res.Reason == "" {
				res.ErrorCode, res.Reason = code, reason
			}
			continue
		}
		_ = client.Close()
	}
	res.Latency = time.Since(res.CheckedAt)
	if len(failures) == 0 {
		res.OK = true
		return res
	}
	res.Error = strings.Join(failures, "; ")
	if len(a.hosts) > 1 {
		res.Reason += fmt.Sprintf(" (%d of %d hosts failed)", len(failures), len(a.hosts))
	}
	return res
}
