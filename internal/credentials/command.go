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

package credentials

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// CommandStoreName is the name the command store is registered under
// (CREDENTIAL_STORE=command).
const CommandStoreName = "command"

// Keys of the configuration map the command store's factory reads.
const (
	// CommandConfigCommand is the command line (required).
	CommandConfigCommand = "command"
	// CommandConfigReloadIn is the reload interval in seconds; 0 or empty
	// runs the command only at startup.
	CommandConfigReloadIn = "reload_in"
	// CommandConfigTimeout is the time limit of one run in seconds; empty
	// means DefaultCommandTimeout.
	CommandConfigTimeout = "timeout"
	// CommandConfigFormat is the output format, FormatDotenv (default) or
	// FormatJSON.
	CommandConfigFormat = "format"
	// CommandConfigJSONPath is the dot-separated path to the JSON object that
	// holds the credentials, e.g. "data.data"; empty selects the top level.
	CommandConfigJSONPath = "json_path"
)

// Output formats of the command.
const (
	// FormatDotenv reads KEY=value lines (see parseDotenv).
	FormatDotenv = "dotenv"
	// FormatJSON reads a JSON object and flattens it (see parseJSONOutput).
	FormatJSON = "json"
)

// ReloadInKey is the reserved output key with which the command sets the
// number of seconds until its next run. It is not a credential.
const ReloadInKey = "RELOAD_IN"

const (
	// DefaultCommandTimeout bounds a run when no timeout is configured.
	DefaultCommandTimeout = 30 * time.Second
	// maxCommandOutput is the most stdout a run may write.
	maxCommandOutput = 1 << 20
	// maxStderrLog is how much of stderr is logged.
	maxStderrLog = 4 << 10
	// firstRetryDelay is the wait after the first failed refresh; it doubles
	// with each further failure, up to the interval in force.
	firstRetryDelay = 30 * time.Second
	// commandWaitDelay bounds the wait for the output pipes after the command
	// exited or was killed, in case a grandchild keeps them open.
	commandWaitDelay = 5 * time.Second
)

func init() {
	Register(CommandStoreName, func(cfg map[string]string) (CredentialStore, error) {
		opts, err := ParseCommandStoreConfig(cfg)
		if err != nil {
			return nil, err
		}
		s, err := NewCommandStore(opts)
		if err != nil {
			return nil, err
		}
		if err := s.Load(context.Background()); err != nil {
			return nil, err
		}
		return s, nil
	})
}

// CommandStoreOptions configures a [CommandStore].
type CommandStoreOptions struct {
	// Command is the command line, split into arguments by shell word rules
	// and run without a shell.
	Command string
	// Interval is the time between successful runs; 0 runs the command
	// only once. A RELOAD_IN line in the output takes precedence.
	Interval time.Duration
	// Timeout bounds a run; 0 means DefaultCommandTimeout.
	Timeout time.Duration
	// Format is the output format, FormatDotenv (also when empty) or
	// FormatJSON.
	Format string
	// JSONPath selects the object that holds the credentials in JSON
	// output, dot-separated; empty selects the top level. Only with
	// FormatJSON.
	JSONPath string
	// Logger receives run outcomes, never values; nil means slog.Default().
	Logger *slog.Logger
}

// ParseCommandStoreConfig reads the factory configuration of the command
// store. Integers are parsed strictly: a typo stops the start instead of
// putting a default in place of the interval the operator meant.
func ParseCommandStoreConfig(cfg map[string]string) (CommandStoreOptions, error) {
	opts := CommandStoreOptions{Command: strings.TrimSpace(cfg[CommandConfigCommand])}
	if opts.Command == "" {
		return opts, errors.New("credential store command: no command configured (TOOLMESH_CREDENTIAL_COMMAND)")
	}
	reload, err := seconds(cfg[CommandConfigReloadIn], 0)
	if err != nil {
		return opts, fmt.Errorf("credential store command: reload interval (TOOLMESH_CREDENTIAL_RELOAD_IN): %w", err)
	}
	timeout, err := seconds(cfg[CommandConfigTimeout], DefaultCommandTimeout)
	if err != nil {
		return opts, fmt.Errorf("credential store command: timeout (TOOLMESH_CREDENTIAL_COMMAND_TIMEOUT): %w", err)
	}
	if timeout == 0 {
		return opts, errors.New("credential store command: timeout (TOOLMESH_CREDENTIAL_COMMAND_TIMEOUT) must be at least one second")
	}
	opts.Interval, opts.Timeout = reload, timeout
	opts.Format = strings.TrimSpace(cfg[CommandConfigFormat])
	opts.JSONPath = strings.TrimSpace(cfg[CommandConfigJSONPath])
	if _, _, err := outputFormat(opts.Format, opts.JSONPath); err != nil {
		return opts, err
	}
	return opts, nil
}

// outputFormat checks the output format and splits the JSON path.
func outputFormat(name, jsonPath string) (format string, path []string, err error) {
	switch name {
	case "", FormatDotenv:
		if jsonPath != "" {
			return "", nil, fmt.Errorf("credential store command: a JSON path (TOOLMESH_CREDENTIAL_JSON_PATH) needs TOOLMESH_CREDENTIAL_FORMAT=%s", FormatJSON)
		}
		return FormatDotenv, nil, nil
	case FormatJSON:
		if jsonPath == "" || jsonPath == "." {
			return FormatJSON, nil, nil
		}
		path = strings.Split(jsonPath, ".")
		for _, p := range path {
			if p == "" {
				return "", nil, fmt.Errorf("credential store command: JSON path %q has an empty segment", jsonPath)
			}
		}
		return FormatJSON, path, nil
	default:
		return "", nil, fmt.Errorf("credential store command: unknown output format %q (TOOLMESH_CREDENTIAL_FORMAT must be %s or %s)", name, FormatDotenv, FormatJSON)
	}
}

// seconds parses a non-negative number of seconds; empty yields fallback.
func seconds(v string, fallback time.Duration) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%q is not a non-negative number of seconds", v)
	}
	return time.Duration(n) * time.Second, nil
}

// CommandStore implements CredentialStore with values a command prints in
// dotenv format, typically a decryption such as `sops -d --output-type
// dotenv`, or as JSON, such as `vault kv get -format=json` with a path to the
// object that holds them. The values live only in a map in memory: never in
// the process environment (so neither in a container configuration nor in
// stdio children) and never in the log.
//
// A successful run replaces the whole set atomically; keys it no longer
// prints are gone. A failed run keeps the previous set and is retried with
// backoff. The command can set the time to its next run with a RELOAD_IN
// key, which suits short-lived tokens.
type CommandStore struct {
	argv     []string
	interval time.Duration
	timeout  time.Duration
	format   string
	jsonPath []string
	logger   *slog.Logger

	// retryDelay is the wait after the first failed refresh.
	retryDelay time.Duration
	// unit is the length of a RELOAD_IN second; shorter only in tests.
	unit time.Duration
	now  func() time.Time

	set         atomic.Pointer[commandSet]
	successes   atomic.Uint64
	failures    atomic.Uint64
	lastSuccess atomic.Int64 // UnixNano of the last successful run, 0 before it
	period      atomic.Int64 // time to the next run after the last success; 0 = none
}

// commandSet is one complete result of the command.
type commandSet struct {
	vars map[string]string
}

// NewCommandStore validates the options and returns a store without values.
// Call [CommandStore.Load] before use and [CommandStore.Run] to refresh.
func NewCommandStore(opts CommandStoreOptions) (*CommandStore, error) {
	argv, err := splitCommandLine(opts.Command)
	if err != nil {
		return nil, fmt.Errorf("credential store command: %w", err)
	}
	if opts.Interval < 0 {
		return nil, errors.New("credential store command: negative reload interval")
	}
	format, jsonPath, err := outputFormat(opts.Format, opts.JSONPath)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &CommandStore{
		argv:       argv,
		interval:   opts.Interval,
		timeout:    timeout,
		format:     format,
		jsonPath:   jsonPath,
		logger:     logger.With("credential_store", CommandStoreName),
		retryDelay: firstRetryDelay,
		unit:       time.Second,
		now:        time.Now,
	}, nil
}

// Load runs the command for the first time. An error means the store has no
// values; ToolMesh does not start with it.
func (s *CommandStore) Load(ctx context.Context) error {
	if err := s.refresh(ctx); err != nil {
		return fmt.Errorf("credential store command: first run failed: %w", err)
	}
	return nil
}

// Run refreshes the values until ctx is done: after the interval in force
// when the last run succeeded, and after a growing delay when a run failed.
// It returns at once when no further run is due.
func (s *CommandStore) Run(ctx context.Context) {
	delay := time.Duration(s.period.Load())
	var retry time.Duration
	for delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		if err := s.refresh(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			retry = s.nextRetry(retry)
			s.logger.Warn("credential command failed, keeping the current credentials",
				"error", err, "retry_in", retry.String())
			delay = retry
			continue
		}
		if retry > 0 {
			s.logger.Info("credential command succeeded again")
		}
		retry = 0
		delay = time.Duration(s.period.Load())
	}
}

// nextRetry doubles the previous retry delay, starting at retryDelay and
// never exceeding the interval in force.
func (s *CommandStore) nextRetry(prev time.Duration) time.Duration {
	next := s.retryDelay
	if prev > 0 {
		next = prev * 2
	}
	if limit := time.Duration(s.period.Load()); limit > 0 && next > limit {
		next = limit
	}
	return next
}

// refresh runs the command once and, on success, replaces the set.
func (s *CommandStore) refresh(ctx context.Context) error {
	vars, reloadIn, err := s.fetch(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.failures.Add(1)
		}
		return err
	}
	s.apply(vars, reloadIn)
	return nil
}

// apply installs the result of a successful run: the set in one atomic swap,
// then the time to the next run (reloadIn RELOAD_IN units when it is not
// negative, the configured interval otherwise) and the success bookkeeping.
func (s *CommandStore) apply(vars map[string]string, reloadIn int) {
	period := s.interval
	if reloadIn >= 0 {
		period = time.Duration(reloadIn) * s.unit
	}
	old := s.set.Swap(&commandSet{vars: vars})
	s.period.Store(int64(period))
	s.lastSuccess.Store(s.now().UnixNano())
	s.successes.Add(1)

	attrs := []any{"keys", len(vars), "next_run_in", period.String()}
	if old == nil {
		s.logger.Info("credentials loaded from command", attrs...)
		return
	}
	added, removed := keyChanges(old.vars, vars)
	if len(added) > 0 || len(removed) > 0 {
		s.logger.Info("credentials refreshed, keys changed", append(attrs, "added", added, "removed", removed)...)
		return
	}
	s.logger.Debug("credentials refreshed", attrs...)
}

// fetch runs the command and parses its output. reloadIn is the RELOAD_IN
// value in seconds, or -1 when the output has none.
func (s *CommandStore) fetch(ctx context.Context) (vars map[string]string, reloadIn int, err error) {
	runCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	stdout := &cappedBuffer{limit: maxCommandOutput}
	stderr := &cappedBuffer{limit: maxStderrLog, keepGoing: true}
	cmd := exec.CommandContext(runCtx, s.argv[0], s.argv[1:]...) //nolint:gosec // operator-configured command, run without a shell
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = commandWaitDelay
	runErr := cmd.Run()
	// The parsed map holds copies; do not leave the raw output around.
	defer func() { clear(stdout.buf) }()

	if len(stderr.buf) > 0 {
		s.logger.Warn("credential command wrote to stderr",
			"stderr", string(stderr.buf), "stderr_truncated", stderr.exceeded)
	}

	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil:
		return nil, 0, fmt.Errorf("command did not finish within %s", s.timeout)
	case stdout.exceeded:
		return nil, 0, fmt.Errorf("command wrote more than %d bytes to stdout", maxCommandOutput)
	case runErr != nil:
		return nil, 0, fmt.Errorf("command failed: %w", runErr)
	}

	if s.format == FormatJSON {
		vars, err = parseJSONOutput(stdout.buf, s.jsonPath)
	} else {
		vars, err = parseDotenv(stdout.buf)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("parse command output: %w", err)
	}
	reloadIn = -1
	if raw, ok := vars[ReloadInKey]; ok {
		delete(vars, ReloadInKey)
		n, convErr := strconv.Atoi(strings.TrimSpace(raw))
		if convErr != nil || n < 0 {
			return nil, 0, fmt.Errorf("parse command output: %s must be a non-negative number of seconds", ReloadInKey)
		}
		reloadIn = n
	}
	if len(vars) == 0 {
		return nil, 0, errors.New("command printed no credentials")
	}
	return vars, reloadIn, nil
}

// keyChanges lists the keys only in next (added) and only in prev (removed),
// sorted. Key names are not secret; values are never compared or logged.
func keyChanges(prev, next map[string]string) (added, removed []string) {
	for k := range next {
		if _, ok := prev[k]; !ok {
			added = append(added, k)
		}
	}
	for k := range prev {
		if _, ok := next[k]; !ok {
			removed = append(removed, k)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

// vars returns the current set, nil before the first successful run.
func (s *CommandStore) vars() map[string]string {
	if set := s.set.Load(); set != nil {
		return set.vars
	}
	return nil
}

// Get returns the value of CREDENTIAL_<NAME> from the last successful run.
func (s *CommandStore) Get(_ context.Context, logicalName string, _ TenantInfo) (string, error) {
	val := s.vars()["CREDENTIAL_"+strings.ToUpper(logicalName)]
	if val == "" {
		return "", fmt.Errorf("credential %q not found: %w", logicalName, ErrCredentialNotFound)
	}
	return val, nil
}

// ListByPrefix returns all non-empty CREDENTIAL_<PREFIX>* values of the last
// successful run, keyed by logical name (without CREDENTIAL_).
func (s *CommandStore) ListByPrefix(_ context.Context, prefix string, _ TenantInfo) (map[string]string, error) {
	keyPrefix := "CREDENTIAL_" + strings.ToUpper(prefix)
	result := make(map[string]string)
	for key, val := range s.vars() {
		if val != "" && strings.HasPrefix(key, keyPrefix) {
			result[strings.TrimPrefix(key, "CREDENTIAL_")] = val
		}
	}
	return result, nil
}

// LookupKey returns the value the last successful run printed for key.
func (s *CommandStore) LookupKey(key string) (string, bool) {
	val, ok := s.vars()[key]
	return val, ok
}

// Healthy reports an error before the first successful run, and when the
// last success lies more than two intervals back. Without a further run due
// the store stays healthy once loaded.
func (s *CommandStore) Healthy(_ context.Context) error {
	if s.set.Load() == nil {
		return errors.New("credential store command: no credentials loaded")
	}
	period := time.Duration(s.period.Load())
	if period == 0 {
		return nil
	}
	since := s.now().Sub(s.LastSuccess())
	if since > 2*period {
		return fmt.Errorf("credential store command: last successful run %s ago, more than twice the interval of %s",
			since.Round(time.Second), period)
	}
	return nil
}

// RunCounts returns the number of successful and failed runs so far.
func (s *CommandStore) RunCounts() (successes, failures uint64) {
	return s.successes.Load(), s.failures.Load()
}

// LastSuccess returns the time of the last successful run, zero before it.
func (s *CommandStore) LastSuccess() time.Time {
	n := s.lastSuccess.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// errOutputLimit stops copying a command's stdout once it is too large.
var errOutputLimit = errors.New("output limit exceeded")

// cappedBuffer collects up to limit bytes. Beyond that it records the excess
// and either fails the write (stdout: the command is cut off) or drops the
// rest (stderr: only the start is logged).
type cappedBuffer struct {
	buf       []byte
	limit     int
	exceeded  bool
	keepGoing bool
}

// Write implements io.Writer.
func (b *cappedBuffer) Write(p []byte) (int, error) {
	room := b.limit - len(b.buf)
	if len(p) <= room {
		b.buf = append(b.buf, p...)
		return len(p), nil
	}
	b.buf = append(b.buf, p[:room]...)
	b.exceeded = true
	if b.keepGoing {
		return len(p), nil
	}
	return room, errOutputLimit
}
