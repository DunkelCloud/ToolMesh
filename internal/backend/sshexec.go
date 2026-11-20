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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

const (
	// sshDefaultPort is the port of a host written without one.
	sshDefaultPort = "22"
	// sshConnectTimeout bounds the TCP connect and the SSH handshake.
	sshConnectTimeout = 10 * time.Second
	// sshCloseGrace is how long a run waits for the session to end after
	// its connection was closed.
	sshCloseGrace = 2 * time.Second
	// pemMarker starts every private key in PEM form.
	pemMarker = "-----BEGIN"
)

// Reasons of a failed connect that are no transport failure. They appear in
// health results and name no host.
const (
	sshReasonKey         = "ssh_key_unavailable"
	sshReasonKnownHosts  = "ssh_known_hosts_unreadable"
	sshReasonHostUnknown = "ssh_host_key_unknown"
	sshReasonHostKey     = "ssh_host_key_rejected"
	sshReasonAuth        = "ssh_login_refused"
)

// sshConnectError is a connect that failed. It has two readers. A caller
// reads Error: the host and what went wrong, without file paths, credential
// names or steps that are the operator's to take, since an agent told how to
// add a host key might try. The operator reads detail in the log: the cause
// as it occurred and what to do about it.
type sshConnectError struct {
	// code is the transport error code of a health result.
	code string
	// reason is a short name of the failure; for a transport failure it is
	// the code.
	reason string
	// public is the text for callers.
	public string
	// detail is the cause, with what an operator needs to act on it.
	detail error
}

func (e *sshConnectError) Error() string { return e.public }

// Unwrap exposes the cause, so that a canceled call is still recognized.
func (e *sshConnectError) Unwrap() error { return e.detail }

// sshHost is one host of an SSH backend.
type sshHost struct {
	// name is the host as the backends.yaml entry writes it, and the value
	// a call selects it with.
	name string
	// addr is the host with its port, for dialing and for known_hosts.
	addr string
}

// parseSSHHost reads a host written as "host", "host:port" or "[v6]:port".
func parseSSHHost(s string) (sshHost, error) {
	name := strings.TrimSpace(s)
	if name == "" {
		return sshHost{}, errors.New("a host is empty")
	}
	if strings.ContainsAny(name, " \t/@") {
		return sshHost{}, fmt.Errorf("host %q: write the host name or address, with :port when it is not 22; the user goes into ssh.user", name)
	}
	host, port := name, sshDefaultPort
	if h, p, err := net.SplitHostPort(name); err == nil {
		host, port = h, p
	} else if strings.Count(name, ":") == 1 || strings.HasPrefix(name, "[") {
		// One colon or a bracket, and still no host:port: a typo, not a
		// bare IPv6 address.
		return sshHost{}, fmt.Errorf("host %q: %w", name, err)
	}
	if host == "" || port == "" {
		return sshHost{}, fmt.Errorf("host %q has an empty host name or port", name)
	}
	return sshHost{name: name, addr: net.JoinHostPort(host, port)}, nil
}

// sshRun is the outcome of one command.
type sshRun struct {
	exitCode int
	// signal names the signal that ended the command, when one did.
	signal          string
	stdout, stderr  []byte
	stdoutTruncated bool
	stderrTruncated bool
	duration        time.Duration
	// timedOut says the command was still running when its time was up.
	timedOut bool
}

// run connects to host, runs line without a terminal and returns what the
// command wrote and how it ended. The connection is made for this one
// command and closed after it.
//
// timeout bounds everything, the connect included. A command that outlives
// it is sent SIGTERM where the host takes signals, and its connection is
// closed; what it wrote until then is returned with timedOut set.
func (a *SSHAdapter) run(ctx context.Context, host sshHost, line string, timeout time.Duration, maxOutput int64) (*sshRun, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()

	client, err := a.connect(ctx, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()

	// Opening the session and starting the command take no context. Until
	// the command runs, the end of the context closes the connection, so a
	// host that stops answering after the login cannot hold the call.
	setupDone := context.AfterFunc(ctx, func() { _ = client.Close() })
	session, err := client.NewSession()
	if err != nil {
		setupDone()
		return nil, fmt.Errorf("open a session on %s: %w", host.name, contextOr(ctx, err))
	}
	defer func() { _ = session.Close() }()

	stdout := &cappedBuffer{limit: maxOutput}
	stderr := &cappedBuffer{limit: maxOutput}
	session.Stdout = stdout
	session.Stderr = stderr
	err = session.Start(line)
	if !setupDone() && err == nil {
		// The context ended while the command was being started, and the
		// connection is closed. Whether the host started it is not known.
		err = ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("start the command on %s: %w", host.name, contextOr(ctx, err))
	}

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	res := &sshRun{}
	select {
	case err = <-done:
	case <-ctx.Done():
		// Without a terminal the host does not end the command when the
		// connection goes away, so ask first; hosts that take no signal
		// requests ignore it.
		_ = session.Signal(ssh.SIGTERM)
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(sshCloseGrace):
		}
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ctx.Err()
		}
		res.timedOut = true
		err = nil
	}
	res.duration = time.Since(start)
	res.stdout, res.stdoutTruncated = stdout.snapshot()
	res.stderr, res.stderrTruncated = stderr.snapshot()

	var (
		exitErr *ssh.ExitError
		missing *ssh.ExitMissingError
	)
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.exitCode = exitErr.ExitStatus()
		res.signal = exitErr.Signal()
	case errors.As(err, &missing):
		return nil, fmt.Errorf("%s closed the session without an exit status", host.name)
	default:
		return nil, fmt.Errorf("run the command on %s: %w", host.name, err)
	}
	return res, nil
}

// contextOr returns the error of ctx when it has ended, and err otherwise:
// an operation that failed because the context closed its connection
// reports the timeout or the cancellation, not the closed connection.
func contextOr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

// connect opens an authenticated connection to host. The host must present
// a key that known_hosts lists for it; there is no way to connect without
// that check.
//
// Every failure comes back as an *sshConnectError.
func (a *SSHAdapter) connect(ctx context.Context, host sshHost) (*ssh.Client, error) {
	signer, err := a.signer(ctx)
	if err != nil {
		return nil, &sshConnectError{
			code:   HealthErrProtocol,
			reason: sshReasonKey,
			public: "the SSH key of this backend cannot be used, so no connection was made; the ToolMesh log has the reason",
			detail: err,
		}
	}
	hostKey, algorithms, err := a.hostKeyCheck(host)
	if err != nil {
		return nil, &sshConnectError{
			code:   HealthErrProtocol,
			reason: sshReasonKnownHosts,
			public: "the known_hosts file of this backend cannot be read, so no connection was made; the ToolMesh log has the reason",
			detail: err,
		}
	}
	cfg := &ssh.ClientConfig{
		User:              a.user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   hostKey,
		HostKeyAlgorithms: algorithms,
		Timeout:           sshConnectTimeout,
	}

	dialCtx, cancel := context.WithTimeout(ctx, sshConnectTimeout)
	defer cancel()
	conn, err := a.dial(dialCtx, "tcp", host.addr)
	if err != nil {
		code := classifyTransportError(err)
		return nil, &sshConnectError{
			code:   code,
			reason: code,
			public: fmt.Sprintf("connect to %s: %s", host.name, transportErrorMessage(err)),
			detail: fmt.Errorf("connect to %s: %w", host.name, err),
		}
	}
	// The handshake has no context of its own; a deadline on the
	// connection bounds it.
	deadline, _ := dialCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	c, chans, reqs, err := ssh.NewClientConn(conn, host.addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, a.handshakeError(host, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// handshakeError explains a failed handshake to its two readers.
func (a *SSHAdapter) handshakeError(host sshHost, err error) *sshConnectError {
	var (
		keyErr     *knownhosts.KeyError
		revokedErr *knownhosts.RevokedError
	)
	e := &sshConnectError{code: HealthErrProtocol}
	switch {
	case errors.As(err, &keyErr) && len(keyErr.Want) == 0:
		e.reason = sshReasonHostUnknown
		e.public = fmt.Sprintf("the key of %s is not among the host keys this backend knows, so nothing was sent to the host; an operator has to add it", host.name)
		e.detail = fmt.Errorf("connect to %s: %w; %s", host.name, err, a.unknownHostHelp(host))
	case errors.As(err, &keyErr):
		e.reason = sshReasonHostKey
		e.public = fmt.Sprintf("%s presents another key than the one this backend knows for it, so nothing was sent to the host; an operator has to find out why the key changed", host.name)
		e.detail = fmt.Errorf("connect to %s: %w; the host presents another key than %s lists for it. Replace the line only after you know why the key changed", host.name, err, a.knownHosts)
	case errors.As(err, &revokedErr):
		e.reason = sshReasonHostKey
		e.public = fmt.Sprintf("the key of %s is revoked, so nothing was sent to the host", host.name)
		e.detail = fmt.Errorf("connect to %s: %w; %s marks the host's key as revoked", host.name, err, a.knownHosts)
	case strings.Contains(err.Error(), "unable to authenticate"):
		e.reason = sshReasonAuth
		e.public = fmt.Sprintf("%s refused the login of this backend as %s", host.name, a.user)
		e.detail = fmt.Errorf("connect to %s as %s: %w; the host does not accept the backend's key for this account (authorized_keys)", host.name, a.user, err)
	default:
		e.code = classifyTransportError(err)
		e.reason = e.code
		e.public = fmt.Sprintf("connect to %s: the SSH handshake failed", host.name)
		e.detail = fmt.Errorf("connect to %s as %s: %w", host.name, a.user, err)
	}
	return e
}

// unknownHostHelp says how a host key gets into known_hosts.
func (a *SSHAdapter) unknownHostHelp(host sshHost) string {
	h, port, _ := net.SplitHostPort(host.addr)
	scan := "ssh-keyscan " + h
	if port != sshDefaultPort {
		scan = "ssh-keyscan -p " + port + " " + h
	}
	return fmt.Sprintf("%s lists no key for %s. Add the host's key, for example with `%s >> %s`, and compare its fingerprint with the host's own", a.knownHosts, host.name, scan, a.knownHosts)
}

// hostKeyCheck returns the check of the host's key against known_hosts and
// the key algorithms to ask the host for. The file is read for every
// connection, so a changed file takes effect without a restart.
//
// The algorithms are those of the keys the file lists for the host: a host
// with several keys would otherwise present whichever the handshake prefers,
// and the check would fail although a listed key exists.
func (a *SSHAdapter) hostKeyCheck(host sshHost) (ssh.HostKeyCallback, []string, error) {
	check, err := knownhosts.New(a.knownHosts)
	if err != nil {
		return nil, nil, fmt.Errorf("read known_hosts: %w", err)
	}
	// A key that matches nothing makes the check name the keys it knows.
	var keyErr *knownhosts.KeyError
	probeErr := check(host.addr, &net.TCPAddr{IP: net.IPv4zero, Port: 22}, probeHostKey())
	if !errors.As(probeErr, &keyErr) || len(keyErr.Want) == 0 {
		// No plain key is listed. A host certificate may still be
		// accepted (@cert-authority), so the handshake decides.
		return check, nil, nil
	}
	seen := make(map[string]bool)
	var algorithms []string
	for _, known := range keyErr.Want {
		for _, algo := range hostKeyAlgorithms(known.Key.Type()) {
			if !seen[algo] {
				seen[algo] = true
				algorithms = append(algorithms, algo)
			}
		}
	}
	return check, algorithms, nil
}

// hostKeyAlgorithms returns the signature algorithms a host key of the
// given type can be asked for.
func hostKeyAlgorithms(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

var (
	probeKeyOnce sync.Once
	probeKey     ssh.PublicKey
)

// probeHostKey returns a public key no host has: a fresh one per process.
func probeHostKey() ssh.PublicKey {
	probeKeyOnce.Do(func() {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return
		}
		probeKey, _ = ssh.NewPublicKey(pub)
	})
	return probeKey
}

// keyCache holds the parsed private key of an adapter, so that a key under
// a passphrase is not decrypted for every command.
type keyCache struct {
	mu     sync.Mutex
	digest [sha256.Size]byte
	signer ssh.Signer
}

// signer returns the private key the backend logs in with. The key comes
// from the credential store or from a file, its passphrase from the
// credential store. Both are read for every connection and the parsed key is
// reused while the key material is the same, so a rotated key takes effect
// without a restart.
func (a *SSHAdapter) signer(ctx context.Context) (ssh.Signer, error) {
	material, source, err := a.keyMaterial(ctx)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(material)

	a.key.mu.Lock()
	defer a.key.mu.Unlock()
	if a.key.signer != nil && a.key.digest == digest {
		return a.key.signer, nil
	}

	signer, err := ssh.ParsePrivateKey(material)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		signer, err = a.decryptKey(ctx, material, source)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("the SSH key from %s cannot be read: %w", source, err)
	}
	a.key.digest, a.key.signer = digest, signer
	return signer, nil
}

// decryptKey opens a private key that is protected by a passphrase.
func (a *SSHAdapter) decryptKey(ctx context.Context, material []byte, source string) (ssh.Signer, error) {
	if a.passphraseCredential == "" {
		return nil, fmt.Errorf("the SSH key from %s is protected by a passphrase: name the credential that holds it in ssh.passphrase_credential", source)
	}
	passphrase, err := a.creds.Get(ctx, a.passphraseCredential, credentials.TenantInfo{})
	if err != nil {
		return nil, fmt.Errorf("passphrase of the SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKeyWithPassphrase(material, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("the passphrase in credential %q does not open the SSH key from %s: %w", a.passphraseCredential, source, err)
	}
	return signer, nil
}

// keyMaterial returns the private key in PEM form and where it came from.
func (a *SSHAdapter) keyMaterial(ctx context.Context) (material []byte, source string, err error) {
	if a.keyFile != "" {
		data, err := os.ReadFile(a.keyFile) //nolint:gosec // path from the operator's backends.yaml
		if err != nil {
			return nil, "", fmt.Errorf("read the SSH key file: %w", err)
		}
		return data, "file " + a.keyFile, nil
	}
	value, err := a.creds.Get(ctx, a.keyCredential, credentials.TenantInfo{})
	if err != nil {
		return nil, "", fmt.Errorf("SSH key: %w", err)
	}
	source = fmt.Sprintf("credential %q", a.keyCredential)
	material, err = normalizeKeyMaterial(value)
	if err != nil {
		return nil, "", fmt.Errorf("the SSH key from %s cannot be read: %w", source, err)
	}
	return material, source, nil
}

// normalizeKeyMaterial brings a private key from a credential store into
// PEM form. A store that holds one line per value cannot carry a PEM block
// as it is, so two single-line forms are read as well: the block with \n
// written out for every line break, and the whole block in base64.
func normalizeKeyMaterial(value string) ([]byte, error) {
	v := strings.TrimSpace(value)
	if !strings.Contains(v, pemMarker) {
		decoded, err := decodeBase64(v)
		if err != nil || !bytes.Contains(decoded, []byte(pemMarker)) {
			return nil, errors.New("the value is neither a private key in PEM form nor one in base64")
		}
		v = strings.TrimSpace(string(decoded))
	}
	if !strings.Contains(v, "\n") {
		v = strings.ReplaceAll(v, `\n`, "\n")
	}
	v = strings.ReplaceAll(v, "\r\n", "\n")
	return []byte(v + "\n"), nil
}

// decodeBase64 decodes standard or URL-safe base64, with or without
// padding, ignoring white space.
func decodeBase64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// cappedBuffer keeps the first limit bytes written to it and remembers
// whether more arrived. It takes writes until the command ends, so a
// command that writes more than fits still runs to its end.
type cappedBuffer struct {
	mu        sync.Mutex
	limit     int64
	buf       bytes.Buffer
	truncated bool
}

// Write implements io.Writer and never fails.
func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.limit - int64(b.buf.Len()); room < int64(len(p)) {
		b.truncated = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	b.buf.Write(p)
	return len(p), nil
}

// snapshot returns a copy of what was kept and whether output was dropped.
func (b *cappedBuffer) snapshot() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes()), b.truncated
}
