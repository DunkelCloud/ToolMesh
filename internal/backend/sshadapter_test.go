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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/sshcmd"
)

const (
	sshTestUser       = "ops"
	sshTestKeyCred    = "web_ssh_key"            //nolint:gosec // name of a credential, not its value
	sshTestPassCred   = "web_ssh_key_passphrase" //nolint:gosec // name of a credential, not its value
	sshTestPassphrase = "correct horse"          //nolint:gosec // test fixture, not a credential
	sshTestBackend    = "web"
	sshToolSay        = "say"
	sshToolProbe      = "probe"
	sshToolHang       = "hang"
	sshParamHost      = "host"
	sshParamWord      = "word"
	sshParamCode      = "code"
	sshExampleHost    = "web1.example.com"
	sshChannelSession = "session"
	sshRequestExec    = "exec"
)

const sshTestCommands = `
backend:
  type: ssh
  description: Test commands
  tools:
    say:
      description: Print a word
      access: read
      argv: [echo, "{word}"]
      params:
        word: {pattern: ".*"}
    probe:
      description: Answer with an exit code
      access: read
      argv: [exit-with, "{code}"]
      success_exit_codes: [0, 3]
      params:
        code: {type: integer, max: 255}
    flood:
      description: Write a lot
      access: read
      argv: [flood]
      max_output: 1KB
    hang:
      description: Never end
      access: write
      argv: [hang]
      timeout: 300ms
`

// sshTestServer is an SSH server in the test process. It runs no program:
// handler stands for the host and decides what a command line does.
type sshTestServer struct {
	addr    string
	hostKey ssh.Signer

	mu       sync.Mutex
	commands []string
	requests []string
	// stalled makes the server leave session requests unanswered: a host
	// that accepts the login and then says nothing.
	stalled bool
}

// sshTestHandler stands for the programs of the host. done closes when the
// client asks to end the command or goes away.
type sshTestHandler func(command string, stdout, stderr io.Writer, done <-chan struct{}) int

// defaultSSHHandler implements the programs the test commands name.
func defaultSSHHandler(command string, stdout, stderr io.Writer, done <-chan struct{}) int {
	switch {
	case strings.HasPrefix(command, "'echo' "):
		_, _ = io.WriteString(stdout, strings.TrimPrefix(command, "'echo' ")+"\n")
		return 0
	case strings.HasPrefix(command, "'exit-with' '"):
		_, _ = io.WriteString(stderr, "exiting\n")
		code := 0
		for _, c := range strings.Trim(strings.TrimPrefix(command, "'exit-with' "), "'") {
			code = code*10 + int(c-'0')
		}
		return code
	case command == "'flood'":
		_, _ = stdout.Write(bytes.Repeat([]byte("x"), 5000))
		_, _ = stderr.Write(bytes.Repeat([]byte("y"), 10))
		return 0
	case command == "'hang'":
		_, _ = io.WriteString(stdout, "started\n")
		<-done
		return 143
	}
	_, _ = io.WriteString(stderr, "unknown command\n")
	return 127
}

// newSSHTestServer starts a server that lets sshTestUser in with the given
// key and no one else.
func newSSHTestServer(t *testing.T, authorized ssh.PublicKey, handler sshTestHandler) *sshTestServer {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == sshTestUser && bytes.Equal(key.Marshal(), authorized.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	cfg.AddHostKey(hostKey)

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &sshTestServer{addr: ln.Addr().String(), hostKey: hostKey}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, cfg, handler)
		}
	}()
	return s
}

func (s *sshTestServer) serve(conn net.Conn, cfg *ssh.ServerConfig, handler sshTestHandler) {
	defer func() { _ = conn.Close() }()
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != sshChannelSession {
			_ = newCh.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		s.mu.Lock()
		stalled := s.stalled
		s.mu.Unlock()
		if stalled {
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			return
		}
		go s.session(ch, requests, handler)
	}
}

func (s *sshTestServer) session(ch ssh.Channel, requests <-chan *ssh.Request, handler sshTestHandler) {
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }
	defer stop()
	for req := range requests {
		s.mu.Lock()
		s.requests = append(s.requests, req.Type)
		s.mu.Unlock()
		switch req.Type {
		case sshRequestExec:
			var payload struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			s.mu.Lock()
			s.commands = append(s.commands, payload.Command)
			s.mu.Unlock()
			_ = req.Reply(true, nil)
			go func() {
				code := handler(payload.Command, ch, ch.Stderr(), done)
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)})) //nolint:gosec // test exit codes are small
				_ = ch.Close()
			}()
		case "signal":
			stop()
			_ = req.Reply(true, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// seen returns the command lines and the session requests the server got.
func (s *sshTestServer) seen() (commands, requests []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...), append([]string(nil), s.requests...)
}

// sshTestKey is a client key in the forms a backend can be given it.
type sshTestKey struct {
	public    ssh.PublicKey
	pem       string // unencrypted, OpenSSH format
	encrypted string // under sshTestPassphrase
}

func newSSHTestKey(t *testing.T) sshTestKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(sshTestPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	return sshTestKey{
		public:    signer.PublicKey(),
		pem:       string(pem.EncodeToMemory(plain)),
		encrypted: string(pem.EncodeToMemory(enc)),
	}
}

// writeKnownHosts writes a known_hosts file with the keys of the servers.
func writeKnownHosts(t *testing.T, servers ...*sshTestServer) string {
	t.Helper()
	lines := make([]string, 0, len(servers))
	for _, s := range servers {
		lines = append(lines, knownhosts.Line([]string{s.addr}, s.hostKey.PublicKey()))
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// newTestSSHAdapter builds an adapter for the test commands.
func newTestSSHAdapter(t *testing.T, cfg SSHConfig, creds map[string]string, opts SSHAdapterOptions) *SSHAdapter {
	t.Helper()
	spec, err := sshcmd.ParseBytes([]byte(sshTestCommands))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User == "" {
		cfg.User = sshTestUser
	}
	opts.Name = sshTestBackend
	opts.SSH = cfg
	a, err := NewSSHAdapter(spec, &testCredStore{creds: creds}, slog.New(slog.DiscardHandler), opts)
	if err != nil {
		t.Fatalf("NewSSHAdapter: %v", err)
	}
	return a
}

// sshFixture is one server, a key it accepts and an adapter that uses both.
func sshFixture(t *testing.T) (*sshTestServer, *SSHAdapter) {
	t.Helper()
	key := newSSHTestKey(t)
	server := newSSHTestServer(t, key.public, defaultSSHHandler)
	adapter := newTestSSHAdapter(t, SSHConfig{
		Hosts:         []string{server.addr},
		KnownHosts:    writeKnownHosts(t, server),
		KeyCredential: sshTestKeyCred,
	}, map[string]string{sshTestKeyCred: key.pem}, SSHAdapterOptions{})
	return server, adapter
}

// connectTexts returns the two texts of a failed connect: what the caller
// reads and what the log carries. The caller's text must hold nothing of
// the operator's: no path of the backend's files and no step to take on
// the ToolMesh host.
func connectTexts(t *testing.T, adapter *SSHAdapter, err error) (public, detail string) {
	t.Helper()
	var connErr *sshConnectError
	if !errors.As(err, &connErr) {
		t.Fatalf("err = %v, want a connect error", err)
	}
	public = err.Error()
	for _, private := range []string{adapter.knownHosts, adapter.keyFile, "ssh-keyscan", "passphrase_credential", sshTestKeyCred} {
		if private != "" && strings.Contains(public, private) {
			t.Errorf("the caller's text carries %q: %s", private, public)
		}
	}
	return public, connErr.detail.Error()
}

func decodeSSHResult(t *testing.T, result *ToolResult) sshResult {
	t.Helper()
	if result == nil || len(result.Content) != 1 {
		t.Fatalf("result = %+v, want one content block", result)
	}
	text, _ := result.Content[0].(map[string]any)[contentTypeText].(string)
	var out sshResult
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("result text is no JSON object: %v\n%s", err, text)
	}
	return out
}

func TestSSHAdapter_Execute(t *testing.T) {
	server, adapter := sshFixture(t)

	result, err := adapter.Execute(context.Background(), sshToolSay, map[string]any{sshParamWord: "hello; reboot"})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Errorf("a command that exits with 0 is an error result: %+v", result)
	}
	out := decodeSSHResult(t, result)
	if out.Host != server.addr || out.Command != `'echo' 'hello; reboot'` {
		t.Errorf("host %q, command %s", out.Host, out.Command)
	}
	if out.ExitCode == nil || *out.ExitCode != 0 || out.Stdout != "'hello; reboot'\n" || out.Stderr != "" {
		t.Errorf("result = %+v", out)
	}
	if result.Metadata[metadataKeyTransport] != transportTypeSSH || result.Metadata[metadataKeyExitCode] != 0 {
		t.Errorf("metadata = %v", result.Metadata)
	}

	commands, requests := server.seen()
	if !reflect.DeepEqual(commands, []string{`'echo' 'hello; reboot'`}) {
		t.Errorf("the host received %q", commands)
	}
	// One exec request and nothing else: no terminal, no environment, no
	// forwarding.
	if !reflect.DeepEqual(requests, []string{sshRequestExec}) {
		t.Errorf("session requests = %v, want [exec]", requests)
	}
}

func TestSSHAdapter_ExitCodes(t *testing.T) {
	_, adapter := sshFixture(t)
	tests := []struct {
		code    int
		isError bool
	}{
		{0, false},
		{3, false}, // listed in success_exit_codes
		{1, true},
		{255, true},
	}
	for _, tt := range tests {
		result, err := adapter.Execute(context.Background(), sshToolProbe, map[string]any{sshParamCode: tt.code})
		if err != nil {
			t.Fatal(err)
		}
		out := decodeSSHResult(t, result)
		if out.ExitCode == nil || *out.ExitCode != tt.code || out.Stderr != "exiting\n" {
			t.Errorf("exit code %d: result = %+v", tt.code, out)
		}
		if result.IsError != tt.isError {
			t.Errorf("exit code %d: IsError = %v, want %v", tt.code, result.IsError, tt.isError)
		}
	}
}

func TestSSHAdapter_OutputLimit(t *testing.T) {
	_, adapter := sshFixture(t)
	result, err := adapter.Execute(context.Background(), "flood", nil)
	if err != nil {
		t.Fatal(err)
	}
	out := decodeSSHResult(t, result)
	if len(out.Stdout) != 1024 || !out.StdoutTruncated {
		t.Errorf("stdout has %d bytes, truncated %v; want 1024 and true", len(out.Stdout), out.StdoutTruncated)
	}
	if out.Stderr != "yyyyyyyyyy" || out.StderrTruncated {
		t.Errorf("stderr = %q, truncated %v", out.Stderr, out.StderrTruncated)
	}
	if result.IsError {
		t.Error("a command whose output was cut is an error result")
	}
}

func TestSSHAdapter_Timeout(t *testing.T) {
	server, adapter := sshFixture(t)
	start := time.Now()
	result, err := adapter.Execute(context.Background(), sshToolHang, nil)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the call took %s with a timeout of 300ms", elapsed)
	}
	out := decodeSSHResult(t, result)
	if !result.IsError || !out.TimedOut || out.ExitCode != nil {
		t.Errorf("IsError %v, result = %+v", result.IsError, out)
	}
	if out.Stdout != "started\n" || !strings.Contains(out.Error, "did not end within 300ms") {
		t.Errorf("stdout %q, error %q", out.Stdout, out.Error)
	}
	if result.Metadata[metadataKeyErrorCode] != dadl.ErrCodeTimeout {
		t.Errorf("metadata = %v", result.Metadata)
	}
	if _, requests := server.seen(); !reflect.DeepEqual(requests, []string{sshRequestExec, "signal"}) {
		t.Errorf("session requests = %v, want the command to be asked to end", requests)
	}
}

func TestSSHAdapter_CanceledCall(t *testing.T) {
	_, adapter := sshFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	if _, err := adapter.Execute(ctx, sshToolHang, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// A host that accepts the login and then stops answering holds a call no
// longer than the command's timeout.
func TestSSHAdapter_StalledHost(t *testing.T) {
	server, adapter := sshFixture(t)
	server.mu.Lock()
	server.stalled = true
	server.mu.Unlock()

	start := time.Now()
	_, err := adapter.Execute(context.Background(), sshToolHang, nil)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "open a session on") {
		t.Errorf("err = %v, want the timeout of the command while the session was opened", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the call took %s with a timeout of 300ms", elapsed)
	}
	if commands, _ := server.seen(); len(commands) != 0 {
		t.Errorf("the host received %q", commands)
	}
}

func TestSSHAdapter_RefusedArguments(t *testing.T) {
	server, adapter := sshFixture(t)
	tests := []struct {
		tool   string
		params map[string]any
		want   string
	}{
		{sshToolSay, map[string]any{}, `missing required parameter "word"`},
		{sshToolSay, map[string]any{sshParamWord: "-n"}, `must not start with "-"`},
		{sshToolSay, map[string]any{sshParamWord: "a", sshParamHost: "x"}, `unknown parameter "host"`},
		{sshToolProbe, map[string]any{sshParamCode: 256}, "must be at most 255"},
	}
	for _, tt := range tests {
		result, err := adapter.Execute(context.Background(), tt.tool, tt.params)
		if err != nil {
			t.Fatal(err)
		}
		text, _ := result.Content[0].(map[string]any)[contentTypeText].(string)
		if !result.IsError || !strings.Contains(text, tt.want) {
			t.Errorf("%s %v: IsError %v, text %q, want %q", tt.tool, tt.params, result.IsError, text, tt.want)
		}
		if result.Metadata[metadataKeyErrorCode] != dadl.ErrCodeInvalidInput {
			t.Errorf("%s %v: metadata = %v", tt.tool, tt.params, result.Metadata)
		}
		if _, err := adapter.ValidateToolParams(tt.tool, tt.params); err == nil {
			t.Errorf("%s %v: ValidateToolParams accepted the call", tt.tool, tt.params)
		}
	}
	if commands, _ := server.seen(); len(commands) != 0 {
		t.Errorf("refused calls reached the host: %q", commands)
	}
	if _, err := adapter.Execute(context.Background(), "nope", nil); err == nil {
		t.Error("an unknown tool was executed")
	}
}

func TestSSHAdapter_ValidateToolParams(t *testing.T) {
	_, adapter := sshFixture(t)
	got, err := adapter.ValidateToolParams(sshToolProbe, map[string]any{sshParamCode: "3"})
	if err != nil {
		t.Fatal(err)
	}
	if got[sshParamCode] != float64(3) {
		t.Errorf("code = %#v, want the number 3", got[sshParamCode])
	}
	// A tool of another backend passes unchanged.
	params := map[string]any{"x": 1}
	if got, err := adapter.ValidateToolParams("other", params); err != nil || !reflect.DeepEqual(got, params) {
		t.Errorf("ValidateToolParams of an unknown tool = %v, %v", got, err)
	}
}

func TestSSHAdapter_HostKey(t *testing.T) {
	key := newSSHTestKey(t)
	server := newSSHTestServer(t, key.public, defaultSSHHandler)
	other := newSSHTestServer(t, key.public, defaultSSHHandler)
	creds := map[string]string{sshTestKeyCred: key.pem}

	t.Run("unknown host", func(t *testing.T) {
		adapter := newTestSSHAdapter(t, SSHConfig{
			Hosts:         []string{server.addr},
			KnownHosts:    writeKnownHosts(t, other),
			KeyCredential: sshTestKeyCred,
		}, creds, SSHAdapterOptions{})
		_, err := adapter.Execute(context.Background(), sshToolSay, map[string]any{sshParamWord: "x"})
		public, detail := connectTexts(t, adapter, err)
		if !strings.Contains(public, "is not among the host keys this backend knows") {
			t.Errorf("caller's text = %s", public)
		}
		if !strings.Contains(detail, "lists no key for "+server.addr) || !strings.Contains(detail, "ssh-keyscan -p") {
			t.Errorf("detail = %s", detail)
		}
		if res := adapter.CheckHealth(context.Background()); res.OK || res.Reason != sshReasonHostUnknown {
			t.Errorf("health = %+v", res)
		}
	})

	t.Run("changed host key", func(t *testing.T) {
		// known_hosts lists the key of another server under this address.
		line := knownhosts.Line([]string{server.addr}, other.hostKey.PublicKey())
		path := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		adapter := newTestSSHAdapter(t, SSHConfig{Hosts: []string{server.addr}, KnownHosts: path, KeyCredential: sshTestKeyCred}, creds, SSHAdapterOptions{})
		_, err := adapter.Execute(context.Background(), sshToolSay, map[string]any{sshParamWord: "x"})
		public, detail := connectTexts(t, adapter, err)
		if !strings.Contains(public, "presents another key than the one this backend knows") {
			t.Errorf("caller's text = %s", public)
		}
		if !strings.Contains(detail, "key mismatch") || !strings.Contains(detail, path) {
			t.Errorf("detail = %s", detail)
		}
		if res := adapter.CheckHealth(context.Background()); res.OK || res.Reason != sshReasonHostKey {
			t.Errorf("health = %+v", res)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		adapter := newTestSSHAdapter(t, SSHConfig{Hosts: []string{server.addr}, KnownHosts: filepath.Join(t.TempDir(), "absent"), KeyCredential: sshTestKeyCred}, creds, SSHAdapterOptions{})
		_, err := adapter.Execute(context.Background(), sshToolSay, map[string]any{sshParamWord: "x"})
		public, detail := connectTexts(t, adapter, err)
		if !strings.Contains(public, "known_hosts file of this backend cannot be read") || !strings.Contains(detail, "read known_hosts") {
			t.Errorf("caller's text = %s, detail = %s", public, detail)
		}
		if res := adapter.CheckHealth(context.Background()); res.OK || res.Reason != sshReasonKnownHosts {
			t.Errorf("health = %+v", res)
		}
	})

	if commands, _ := server.seen(); len(commands) != 0 {
		t.Errorf("commands reached a host whose key was not accepted: %q", commands)
	}
}

func TestSSHAdapter_KeySources(t *testing.T) {
	key := newSSHTestKey(t)
	server := newSSHTestServer(t, key.public, defaultSSHHandler)
	known := writeKnownHosts(t, server)
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyFile, []byte(key.encrypted), 0o600); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(key.pem))

	tests := []struct {
		name    string
		cfg     SSHConfig
		creds   map[string]string
		wantErr string
	}{
		{"PEM from the store", SSHConfig{KeyCredential: sshTestKeyCred}, map[string]string{sshTestKeyCred: key.pem}, ""},
		{"PEM with written-out line breaks", SSHConfig{KeyCredential: sshTestKeyCred}, map[string]string{sshTestKeyCred: strings.ReplaceAll(strings.TrimSpace(key.pem), "\n", `\n`)}, ""},
		{"PEM with CRLF", SSHConfig{KeyCredential: sshTestKeyCred}, map[string]string{sshTestKeyCred: strings.ReplaceAll(key.pem, "\n", "\r\n")}, ""},
		{"base64 from the store", SSHConfig{KeyCredential: sshTestKeyCred}, map[string]string{sshTestKeyCred: b64}, ""},
		{"encrypted key and passphrase from the store", SSHConfig{KeyCredential: sshTestKeyCred, PassphraseCredential: sshTestPassCred},
			map[string]string{sshTestKeyCred: key.encrypted, sshTestPassCred: sshTestPassphrase}, ""},
		{"encrypted key file, passphrase from the store", SSHConfig{KeyFile: keyFile, PassphraseCredential: sshTestPassCred},
			map[string]string{sshTestPassCred: sshTestPassphrase}, ""},
		{"passphrase configured for a plain key", SSHConfig{KeyCredential: sshTestKeyCred, PassphraseCredential: sshTestPassCred},
			map[string]string{sshTestKeyCred: key.pem}, ""},
		{"encrypted key without a passphrase credential", SSHConfig{KeyCredential: sshTestKeyCred},
			map[string]string{sshTestKeyCred: key.encrypted}, "protected by a passphrase: name the credential"},
		{"passphrase credential not in the store", SSHConfig{KeyCredential: sshTestKeyCred, PassphraseCredential: sshTestPassCred},
			map[string]string{sshTestKeyCred: key.encrypted}, "passphrase of the SSH key"},
		{"wrong passphrase", SSHConfig{KeyCredential: sshTestKeyCred, PassphraseCredential: sshTestPassCred},
			map[string]string{sshTestKeyCred: key.encrypted, sshTestPassCred: "wrong"}, "does not open the SSH key"},
		{"key credential not in the store", SSHConfig{KeyCredential: sshTestKeyCred}, map[string]string{}, "SSH key:"},
		{"no key in the value", SSHConfig{KeyCredential: sshTestKeyCred}, map[string]string{sshTestKeyCred: "hunter2"}, "neither a private key in PEM form nor one in base64"},
		{"missing key file", SSHConfig{KeyFile: filepath.Join(t.TempDir(), "absent")}, map[string]string{}, "read the SSH key file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.Hosts = []string{server.addr}
			cfg.KnownHosts = known
			adapter := newTestSSHAdapter(t, cfg, tt.creds, SSHAdapterOptions{})
			result, err := adapter.Execute(context.Background(), sshToolSay, map[string]any{sshParamWord: "ok"})
			if tt.wantErr == "" {
				if err != nil || result.IsError {
					t.Fatalf("Execute: %v, %+v", err, result)
				}
				return
			}
			public, detail := connectTexts(t, adapter, err)
			if !strings.Contains(public, "the SSH key of this backend cannot be used") {
				t.Errorf("caller's text = %s", public)
			}
			if !strings.Contains(detail, tt.wantErr) {
				t.Fatalf("detail = %s, want it to contain %q", detail, tt.wantErr)
			}
			for _, secret := range []string{sshTestPassphrase, "hunter2", "wrong"} {
				if strings.Contains(public, secret) || strings.Contains(detail, secret) {
					t.Errorf("an error text carries a credential value: %s / %s", public, detail)
				}
			}
			if res := adapter.CheckHealth(context.Background()); res.OK || res.Reason != sshReasonKey {
				t.Errorf("health = %+v, want reason %s", res, sshReasonKey)
			}
		})
	}
}

func TestSSHAdapter_KeyRotation(t *testing.T) {
	key := newSSHTestKey(t)
	server := newSSHTestServer(t, key.public, defaultSSHHandler)
	store := map[string]string{sshTestKeyCred: key.encrypted, sshTestPassCred: sshTestPassphrase}
	adapter := newTestSSHAdapter(t, SSHConfig{
		Hosts: []string{server.addr}, KnownHosts: writeKnownHosts(t, server),
		KeyCredential: sshTestKeyCred, PassphraseCredential: sshTestPassCred,
	}, store, SSHAdapterOptions{})

	for range 2 {
		if _, err := adapter.Execute(context.Background(), sshToolSay, map[string]any{sshParamWord: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	// The store hands out another key: the next call uses it.
	store[sshTestKeyCred] = newSSHTestKey(t).pem
	_, err := adapter.Execute(context.Background(), sshToolSay, map[string]any{sshParamWord: "ok"})
	public, detail := connectTexts(t, adapter, err)
	if !strings.Contains(public, "refused the login of this backend as "+sshTestUser) || !strings.Contains(detail, "unable to authenticate") {
		t.Errorf("caller's text = %s, detail = %s; want the login with the new key to be refused", public, detail)
	}
	if res := adapter.CheckHealth(context.Background()); res.OK || res.Reason != sshReasonAuth {
		t.Errorf("health = %+v, want reason %s", res, sshReasonAuth)
	}
}

func TestSSHAdapter_SeveralHosts(t *testing.T) {
	key := newSSHTestKey(t)
	first := newSSHTestServer(t, key.public, defaultSSHHandler)
	second := newSSHTestServer(t, key.public, defaultSSHHandler)
	adapter := newTestSSHAdapter(t, SSHConfig{
		Hosts:         []string{first.addr, second.addr},
		KnownHosts:    writeKnownHosts(t, first, second),
		KeyCredential: sshTestKeyCred,
	}, map[string]string{sshTestKeyCred: key.pem}, SSHAdapterOptions{})

	result, err := adapter.Execute(context.Background(), sshToolSay, map[string]any{sshParamWord: "x", sshParamHost: second.addr})
	if err != nil || result.IsError {
		t.Fatalf("Execute: %v, %+v", err, result)
	}
	if out := decodeSSHResult(t, result); out.Host != second.addr {
		t.Errorf("host = %q, want %q", out.Host, second.addr)
	}
	firstCommands, _ := first.seen()
	secondCommands, _ := second.seen()
	if len(firstCommands) != 0 || len(secondCommands) != 1 {
		t.Errorf("first host got %q, second %q", firstCommands, secondCommands)
	}

	for _, params := range []map[string]any{{sshParamWord: "x"}, {sshParamWord: "x", sshParamHost: "198.51.100.7"}} {
		result, err := adapter.Execute(context.Background(), sshToolSay, params)
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Errorf("a call with %v ran", params)
		}
	}

	desc, ok := adapter.LookupTool(sshToolSay)
	if !ok {
		t.Fatal("LookupTool: say not found")
	}
	if got := desc.InputSchema[schemaKeyRequired]; !reflect.DeepEqual(got, []string{sshParamHost, sshParamWord}) {
		t.Errorf("required = %v", got)
	}
	host := desc.InputSchema[schemaKeyProperties].(map[string]any)[sshParamHost].(map[string]any)
	if !reflect.DeepEqual(host["enum"], []any{first.addr, second.addr}) {
		t.Errorf("host enum = %v", host["enum"])
	}
	if !strings.Contains(desc.Description, "The parameter host selects the host: one of "+first.addr) {
		t.Errorf("description = %q", desc.Description)
	}

	if res := adapter.CheckHealth(context.Background()); !res.OK {
		t.Errorf("health = %+v", res)
	}
}

func TestSSHAdapter_Health(t *testing.T) {
	_, adapter := sshFixture(t)
	if res := adapter.CheckHealth(context.Background()); !res.OK || res.Error != "" || res.Latency <= 0 {
		t.Errorf("health = %+v", res)
	}
	if err := adapter.Healthy(context.Background()); err != nil {
		t.Errorf("Healthy: %v", err)
	}
	if !adapter.HasHealthCheck() {
		t.Error("an SSH backend has no health check")
	}

	// A port nobody listens on.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()
	key := newSSHTestKey(t)
	server := newSSHTestServer(t, key.public, defaultSSHHandler)
	down := newTestSSHAdapter(t, SSHConfig{
		Hosts: []string{server.addr, dead}, KnownHosts: writeKnownHosts(t, server), KeyCredential: sshTestKeyCred,
	}, map[string]string{sshTestKeyCred: key.pem}, SSHAdapterOptions{})
	res := down.CheckHealth(context.Background())
	if res.OK || res.ErrorCode != HealthErrConnectionRefused || res.Reason != HealthErrConnectionRefused+" (1 of 2 hosts failed)" {
		t.Errorf("health = %+v", res)
	}
	if strings.Contains(res.Reason, "127.0.0.1") {
		t.Errorf("the reason names a host: %q", res.Reason)
	}
	if err := down.Healthy(context.Background()); err == nil {
		t.Error("Healthy passed with a host down")
	}
}

func TestSSHAdapter_ListTools(t *testing.T) {
	_, adapter := sshFixture(t)
	tools, err := adapter.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
		if tool.Backend != "ssh:"+sshTestBackend || tool.Access == "" {
			t.Errorf("tool %s: backend %q, access %q", tool.Name, tool.Backend, tool.Access)
		}
	}
	if !reflect.DeepEqual(names, []string{"flood", sshToolHang, sshToolProbe, sshToolSay}) {
		t.Errorf("tools = %v", names)
	}
	say, _ := adapter.LookupTool(sshToolSay)
	if !strings.Contains(say.Description, "Runs `echo {word}`.") || say.Access != "read" {
		t.Errorf("say = %+v", say)
	}
	if props := say.InputSchema[schemaKeyProperties].(map[string]any); props[sshParamHost] != nil {
		t.Error("a backend with one host offers the parameter host")
	}

	info := adapter.BackendSummaries()
	if len(info) != 1 || info[0].Name != sshTestBackend || info[0].Description != "Test commands" || info[0].SpecID == "" {
		t.Errorf("summaries = %+v", info)
	}
}

func TestSSHAdapter_IncludeTools(t *testing.T) {
	key := newSSHTestKey(t)
	server := newSSHTestServer(t, key.public, defaultSSHHandler)
	adapter := newTestSSHAdapter(t, SSHConfig{
		Hosts: []string{server.addr}, KnownHosts: writeKnownHosts(t, server), KeyCredential: sshTestKeyCred,
	}, map[string]string{sshTestKeyCred: key.pem}, SSHAdapterOptions{
		IncludeTools:    []string{sshToolSay, "absent"},
		Hint:            "Read the runbook first.",
		HintRequiredFor: []string{hintTestWrite},
	})
	tools, _ := adapter.ListTools(context.Background())
	if len(tools) != 1 || tools[0].Name != sshToolSay || adapter.ToolCount() != 1 {
		t.Errorf("tools = %+v", tools)
	}
	if _, ok := adapter.LookupTool(sshToolHang); ok {
		t.Error("LookupTool finds a command outside include_tools")
	}
	if _, err := adapter.Execute(context.Background(), sshToolHang, nil); err == nil {
		t.Error("a command outside include_tools was executed")
	}
	if info := adapter.BackendSummaries()[0]; info.Hint != "Read the runbook first." || !reflect.DeepEqual(info.HintRequiredFor, []string{hintTestWrite}) {
		t.Errorf("summary = %+v", info)
	}
}

func TestNewSSHAdapter_Refused(t *testing.T) {
	spec, err := sshcmd.ParseBytes([]byte(sshTestCommands))
	if err != nil {
		t.Fatal(err)
	}
	valid := SSHConfig{User: sshTestUser, Hosts: []string{sshExampleHost}, KnownHosts: "known_hosts", KeyCredential: sshTestKeyCred}
	tests := []struct {
		name   string
		change func(*SSHConfig)
		want   string
	}{
		{"no user", func(c *SSHConfig) { c.User = "" }, "ssh.user is missing"},
		{"user with host", func(c *SSHConfig) { c.User = "ops@web1" }, "is not an account name"},
		{"user as option", func(c *SSHConfig) { c.User = "-oProxyCommand=x" }, "is not an account name"},
		{"no hosts", func(c *SSHConfig) { c.Hosts = nil }, "ssh.hosts is empty"},
		{"host with user", func(c *SSHConfig) { c.Hosts = []string{"ops@web1.example.com"} }, "the user goes into ssh.user"},
		{"host with empty port", func(c *SSHConfig) { c.Hosts = []string{"web1.example.com:"} }, "empty host name or port"},
		{"host listed twice", func(c *SSHConfig) { c.Hosts = []string{sshExampleHost, "web1.example.com:22"} }, "twice"},
		{"no known_hosts", func(c *SSHConfig) { c.KnownHosts = "" }, "ssh.known_hosts is missing"},
		{"no key", func(c *SSHConfig) { c.KeyCredential = "" }, "exactly one of ssh.key_credential and ssh.key_file"},
		{"two keys", func(c *SSHConfig) { c.KeyFile = "id" }, "exactly one of ssh.key_credential and ssh.key_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.change(&cfg)
			_, err := NewSSHAdapter(spec, &testCredStore{}, slog.New(slog.DiscardHandler), SSHAdapterOptions{Name: sshTestBackend, SSH: cfg})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
	if _, err := NewSSHAdapter(spec, &testCredStore{}, slog.New(slog.DiscardHandler), SSHAdapterOptions{SSH: valid}); err == nil {
		t.Error("a backend without a name was created")
	}
}

func TestParseSSHHost(t *testing.T) {
	tests := map[string]string{
		sshExampleHost:          "web1.example.com:22",
		"web1.example.com:2222": "web1.example.com:2222",
		"192.0.2.10":            "192.0.2.10:22",
		"2001:db8::1":           "[2001:db8::1]:22",
		"[2001:db8::1]:2222":    "[2001:db8::1]:2222",
	}
	for in, want := range tests {
		host, err := parseSSHHost(in)
		if err != nil || host.addr != want || host.name != in {
			t.Errorf("parseSSHHost(%q) = %+v, %v; want addr %q", in, host, err, want)
		}
	}
	for _, in := range []string{"", "a b", "[2001:db8::1", "ssh://web1"} {
		if _, err := parseSSHHost(in); err == nil {
			t.Errorf("parseSSHHost(%q) passed", in)
		}
	}
}

func TestBackendConfig_SSHEntry(t *testing.T) {
	const src = `
backends:
  - name: web
    transport: ssh
    commands: ssh/linux-host.yaml
    hint: Read the runbook first.
    ssh:
      user: ops
      hosts: [web1.example.com, "web2.example.com:2222"]
      known_hosts: ssh/known_hosts
      key_credential: web_ssh_key
      passphrase_credential: web_ssh_key_passphrase
`
	var cfg BackendConfig
	if err := UnmarshalBackendConfig([]byte(src), &cfg); err != nil {
		t.Fatal(err)
	}
	entry := cfg.Backends[0]
	if entry.Transport != TransportSSH || entry.Commands != "ssh/linux-host.yaml" || entry.SSH == nil {
		t.Fatalf("entry = %+v", entry)
	}
	want := SSHConfig{
		User: "ops", Hosts: []string{sshExampleHost, "web2.example.com:2222"}, KnownHosts: "ssh/known_hosts",
		KeyCredential: sshTestKeyCred, PassphraseCredential: sshTestPassCred,
	}
	if !reflect.DeepEqual(*entry.SSH, want) {
		t.Errorf("ssh = %+v, want %+v", *entry.SSH, want)
	}
	// The block is read strictly, like the rest of the file.
	typo := strings.Replace(src, "known_hosts:", "knownhosts:", 1)
	if err := UnmarshalBackendConfig([]byte(typo), &cfg); err == nil {
		t.Error("an unknown key in the ssh block was accepted")
	}
	// The MCP adapter leaves the entry to the SSH loader.
	if n := NewMCPAdapterFromEntries(cfg.Backends, &testCredStore{}, slog.New(slog.DiscardHandler)).BackendCount(); n != 0 {
		t.Errorf("the MCP adapter registered %d backends for an SSH entry", n)
	}
}
