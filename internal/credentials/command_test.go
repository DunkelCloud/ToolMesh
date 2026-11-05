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
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The test binary doubles as the credential command: run with helperArg as
// its first argument it acts as the helper below instead of running tests.
// No shell is involved, exactly as in production.
const helperArg = "credential-command-helper"

// Helper modes.
const (
	helperPrint = "print" // print the file args[1]; FAIL as content exits 5
	helperFail  = "fail"  // write args[1] to stderr and exit 3
	helperSleep = "sleep" // sleep far beyond any test timeout
	helperFlood = "flood" // write more stdout than the store accepts
	helperNoisy = "noisy" // print args[1] after 10 KiB of stderr
)

const (
	testCredA       = "CREDENTIAL_A" //nolint:gosec // key name, not a credential
	testGen1        = "gen1"
	testGen2        = "gen2"
	testHelperError = "helper: something went wrong"
	testGHToken     = "gh-token" //nolint:gosec // test fixture, not a credential
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == helperArg {
		os.Exit(runCommandHelper(os.Args[2:]))
	}
	os.Exit(m.Run())
}

func runCommandHelper(args []string) int {
	if len(args) == 0 {
		return 64
	}
	switch args[0] {
	case helperPrint:
		data, err := os.ReadFile(args[1]) //nolint:gosec // path from the test's own temp dir
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper: cannot read the output file")
			return 2
		}
		if string(data) == "FAIL\n" {
			fmt.Fprintln(os.Stderr, testHelperError)
			return 5
		}
		_, _ = os.Stdout.Write(data)
		if len(args) > 2 {
			fmt.Fprintln(os.Stderr, args[2])
		}
		return 0
	case helperFail:
		fmt.Fprintln(os.Stderr, args[1])
		fmt.Fprintln(os.Stdout, "CREDENTIAL_A=from-a-failed-run")
		return 3
	case helperSleep:
		time.Sleep(time.Minute)
		return 0
	case helperFlood:
		line := strings.Repeat("x", 1023) + "\n"
		for i := 0; i <= maxCommandOutput/len(line); i++ {
			if _, err := io.WriteString(os.Stdout, line); err != nil {
				return 0
			}
		}
		return 0
	case helperNoisy:
		_, _ = io.WriteString(os.Stderr, strings.Repeat("n", 10<<10))
		_, _ = io.WriteString(os.Stdout, args[1])
		return 0
	}
	return 64
}

// shellQuote quotes s for splitCommandLine.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// helperCommand returns a command line that runs the helper with args.
func helperCommand(t *testing.T, args ...string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	parts := make([]string, 0, 2+len(args))
	parts = append(parts, shellQuote(exe), helperArg)
	for _, a := range args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

// outputFile is a file the print helper copies to stdout.
type outputFile struct {
	t    *testing.T
	path string
}

func newOutputFile(t *testing.T, content string) *outputFile {
	t.Helper()
	f := &outputFile{t: t, path: filepath.Join(t.TempDir(), "out.env")}
	f.set(content)
	return f
}

// set replaces the content. A helper reading at the same moment may see a
// partial file; that is a failed or odd run the tests tolerate.
func (f *outputFile) set(content string) {
	f.t.Helper()
	var err error
	for range 50 {
		if err = os.WriteFile(f.path, []byte(content), 0o600); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatalf("write output file: %v", err)
}

// syncBuffer is a log sink safe for the refresh goroutine and the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newTestStore builds a store that runs the helper with args. RELOAD_IN
// seconds and the first retry delay are shortened so refresh tests run fast.
func newTestStore(t *testing.T, opts CommandStoreOptions, args ...string) (*CommandStore, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	if opts.Command == "" {
		opts.Command = helperCommand(t, args...)
	}
	opts.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s, err := NewCommandStore(opts)
	if err != nil {
		t.Fatalf("NewCommandStore: %v", err)
	}
	s.unit = 20 * time.Millisecond
	s.retryDelay = 10 * time.Millisecond
	return s, logs
}

// runInBackground starts the refresh loop and stops it when the test ends.
func runInBackground(t *testing.T, s *CommandStore) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func getA(s *CommandStore) string {
	v, _ := s.Get(context.Background(), "a", TenantInfo{})
	return v
}

func TestCommandStore_Load(t *testing.T) {
	out := newOutputFile(t, "# from the helper\nCREDENTIAL_GITHUB_TOKEN=gh-token\nCREDENTIAL_GITHUB_APP_KEY=\"multi\\nline\"\n"+
		"CREDENTIAL_EMPTY=\nTOOLMESH_API_KEY=tm-key\nRELOAD_IN=7\n")
	s, logs := newTestStore(t, CommandStoreOptions{}, helperPrint, out.path)
	s.unit = time.Second // no refresh here; keep the health window wide under load
	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ctx := context.Background()

	if got, err := s.Get(ctx, "github_token", TenantInfo{}); err != nil || got != testGHToken {
		t.Errorf("Get(github_token) = %q, %v", got, err)
	}
	if _, err := s.Get(ctx, "empty", TenantInfo{}); err == nil {
		t.Error("an empty value must count as not found")
	}
	if _, err := s.Get(ctx, "missing", TenantInfo{}); err == nil {
		t.Error("expected not found for a missing credential")
	}

	listed, err := s.ListByPrefix(ctx, "GITHUB_", TenantInfo{})
	if err != nil {
		t.Fatalf("ListByPrefix: %v", err)
	}
	want := map[string]string{"GITHUB_TOKEN": testGHToken, "GITHUB_APP_KEY": "multi\nline"}
	if len(listed) != len(want) || listed["GITHUB_TOKEN"] != want["GITHUB_TOKEN"] || listed["GITHUB_APP_KEY"] != want["GITHUB_APP_KEY"] {
		t.Errorf("ListByPrefix = %q, want %q", listed, want)
	}

	if v, ok := s.LookupKey("TOOLMESH_API_KEY"); !ok || v != "tm-key" {
		t.Errorf("LookupKey(TOOLMESH_API_KEY) = %q, %v", v, ok)
	}
	if _, ok := s.LookupKey(ReloadInKey); ok {
		t.Error("RELOAD_IN must not be stored as a value")
	}
	if got := time.Duration(s.period.Load()); got != 7*s.unit {
		t.Errorf("period = %s, want 7 RELOAD_IN units", got)
	}
	if ok, failed := s.RunCounts(); ok != 1 || failed != 0 {
		t.Errorf("RunCounts = %d, %d; want 1, 0", ok, failed)
	}
	if s.LastSuccess().IsZero() {
		t.Error("LastSuccess not set")
	}
	if err := s.Healthy(ctx); err != nil {
		t.Errorf("Healthy: %v", err)
	}
	for _, secret := range []string{testGHToken, "tm-key", "multi"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("log contains the value %q:\n%s", secret, logs)
		}
	}
}

func TestCommandStore_FailedFirstRun(t *testing.T) {
	const secretLine = "this-line-is-a-secret-without-a-key" //nolint:gosec // test fixture, not a credential
	tests := []struct {
		name    string
		args    func(t *testing.T) []string
		command string
		timeout time.Duration
		want    string
	}{
		{name: "non-zero exit code", args: func(*testing.T) []string { return []string{helperFail, testHelperError} }, want: "command failed: exit status 3"},
		{name: "timeout", args: func(*testing.T) []string { return []string{helperSleep} }, timeout: time.Second, want: "did not finish within 1s"},
		{name: "too much output", args: func(*testing.T) []string { return []string{helperFlood} }, want: "more than 1048576 bytes"},
		{name: "empty output", args: func(t *testing.T) []string {
			return []string{helperPrint, newOutputFile(t, "# nothing but a comment\n\n").path}
		}, want: "printed no credentials"},
		{name: "only RELOAD_IN", args: func(t *testing.T) []string {
			return []string{helperPrint, newOutputFile(t, "RELOAD_IN=60\n").path}
		}, want: "printed no credentials"},
		{name: "parse error", args: func(t *testing.T) []string {
			return []string{helperPrint, newOutputFile(t, "CREDENTIAL_A=ok\n"+secretLine+"\n").path}
		}, want: "line 2: expected KEY=value"},
		{name: "invalid RELOAD_IN", args: func(t *testing.T) []string {
			return []string{helperPrint, newOutputFile(t, "CREDENTIAL_A=ok\nRELOAD_IN=soon\n").path}
		}, want: "RELOAD_IN must be a non-negative number"},
		{name: "negative RELOAD_IN", args: func(t *testing.T) []string {
			return []string{helperPrint, newOutputFile(t, "CREDENTIAL_A=ok\nRELOAD_IN=-5\n").path}
		}, want: "RELOAD_IN must be a non-negative number"},
		{name: "missing executable", command: shellQuote(filepath.Join(t.TempDir(), "no-such-binary")), want: "command failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := CommandStoreOptions{Command: tt.command, Timeout: tt.timeout}
			var args []string
			if tt.args != nil {
				args = tt.args(t)
			}
			s, _ := newTestStore(t, opts, args...)
			err := s.Load(context.Background())
			if err == nil {
				t.Fatal("expected Load to fail")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
			if strings.Contains(err.Error(), secretLine) || strings.Contains(err.Error(), "from-a-failed-run") {
				t.Errorf("error %q leaks command output", err)
			}
			if ok, failed := s.RunCounts(); ok != 0 || failed != 1 {
				t.Errorf("RunCounts = %d, %d; want 0, 1", ok, failed)
			}
			if _, ok := s.LookupKey(testCredA); ok {
				t.Error("a failed run must not install values")
			}
			if s.Healthy(context.Background()) == nil {
				t.Error("Healthy must fail before the first successful run")
			}
		})
	}
}

func TestCommandStore_StderrLoggedStdoutNever(t *testing.T) {
	t.Run("success with a warning", func(t *testing.T) {
		out := newOutputFile(t, "CREDENTIAL_A=stdout-secret-1\n")
		s, logs := newTestStore(t, CommandStoreOptions{}, helperPrint, out.path, "helper: key file is world-readable")
		if err := s.Load(context.Background()); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !strings.Contains(logs.String(), "key file is world-readable") {
			t.Errorf("stderr not logged:\n%s", logs)
		}
		if strings.Contains(logs.String(), "stdout-secret-1") {
			t.Errorf("stdout leaked into the log:\n%s", logs)
		}
	})
	t.Run("failure", func(t *testing.T) {
		s, logs := newTestStore(t, CommandStoreOptions{}, helperFail, testHelperError)
		_ = s.Load(context.Background())
		if !strings.Contains(logs.String(), testHelperError) || !strings.Contains(logs.String(), "level=WARN") {
			t.Errorf("stderr of a failed run not logged on WARN:\n%s", logs)
		}
		if strings.Contains(logs.String(), "from-a-failed-run") {
			t.Errorf("stdout leaked into the log:\n%s", logs)
		}
	})
	t.Run("stderr is truncated", func(t *testing.T) {
		s, logs := newTestStore(t, CommandStoreOptions{}, helperNoisy, "CREDENTIAL_A=stdout-secret-2\n")
		if err := s.Load(context.Background()); err != nil {
			t.Fatalf("Load: %v", err)
		}
		text := logs.String()
		if !strings.Contains(text, "stderr_truncated=true") {
			t.Errorf("truncation not reported:\n%.300s", text)
		}
		if strings.Contains(text, strings.Repeat("n", maxStderrLog+1)) {
			t.Error("more than the stderr limit was logged")
		}
		if strings.Contains(text, "stdout-secret-2") {
			t.Error("stdout leaked into the log")
		}
	})
}

func TestCommandStore_RefreshWithConfiguredInterval(t *testing.T) {
	out := newOutputFile(t, "CREDENTIAL_A=gen1\nCREDENTIAL_GONE=soon\n")
	s, _ := newTestStore(t, CommandStoreOptions{Interval: 50 * time.Millisecond}, helperPrint, out.path)
	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	runInBackground(t, s)

	out.set("CREDENTIAL_A=gen2\n")
	waitFor(t, "the refreshed value", func() bool { return getA(s) == testGen2 })
	waitFor(t, "the dropped key to disappear", func() bool {
		_, ok := s.LookupKey("CREDENTIAL_GONE")
		return !ok
	})
}

func TestCommandStore_RefreshWithReloadIn(t *testing.T) {
	// No interval configured: only RELOAD_IN schedules the next run.
	out := newOutputFile(t, "CREDENTIAL_A=gen1\nRELOAD_IN=2\n")
	s, _ := newTestStore(t, CommandStoreOptions{}, helperPrint, out.path)
	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	runInBackground(t, s)

	out.set("CREDENTIAL_A=gen2\nRELOAD_IN=2\n")
	waitFor(t, "the refreshed value", func() bool { return getA(s) == testGen2 })
}

func TestCommandStore_ReloadInOverridesInterval(t *testing.T) {
	out := newOutputFile(t, "CREDENTIAL_A=gen1\nRELOAD_IN=2\n")
	s, _ := newTestStore(t, CommandStoreOptions{Interval: time.Hour}, helperPrint, out.path)
	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := time.Duration(s.period.Load()); got != 2*s.unit {
		t.Fatalf("period = %s, want RELOAD_IN, not the configured hour", got)
	}
	runInBackground(t, s)

	// Without RELOAD_IN the configured interval applies again.
	out.set("CREDENTIAL_A=gen2\n")
	waitFor(t, "the refreshed value", func() bool { return getA(s) == testGen2 })
	waitFor(t, "the configured interval", func() bool { return time.Duration(s.period.Load()) == time.Hour })
}

func TestCommandStore_NoRefreshWithoutInterval(t *testing.T) {
	out := newOutputFile(t, "CREDENTIAL_A=gen1\n")
	s, _ := newTestStore(t, CommandStoreOptions{}, helperPrint, out.path)
	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return although no further run is due")
	}
	if ok, _ := s.RunCounts(); ok != 1 {
		t.Errorf("successful runs = %d, want only the first", ok)
	}
}

func TestCommandStore_FailedRefreshKeepsSet(t *testing.T) {
	out := newOutputFile(t, "CREDENTIAL_A=gen1\n")
	s, logs := newTestStore(t, CommandStoreOptions{Interval: 40 * time.Millisecond}, helperPrint, out.path)
	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	runInBackground(t, s)

	out.set("FAIL\n")
	waitFor(t, "two failed refreshes", func() bool {
		_, failed := s.RunCounts()
		return failed >= 2
	})
	if got := getA(s); got != testGen1 {
		t.Fatalf("after failed runs CREDENTIAL_A = %q, want the previous %q", got, testGen1)
	}
	if !strings.Contains(logs.String(), "keeping the current credentials") {
		t.Errorf("failed refresh not logged:\n%s", logs)
	}

	out.set("CREDENTIAL_A=gen2\n")
	waitFor(t, "recovery", func() bool { return getA(s) == testGen2 })
	waitFor(t, "the recovery to be logged", func() bool { return strings.Contains(logs.String(), "succeeded again") })
}

func TestCommandStore_NextRetry(t *testing.T) {
	s := &CommandStore{retryDelay: 30 * time.Second}
	s.period.Store(int64(100 * time.Second))
	got := make([]time.Duration, 0, 5)
	var d time.Duration
	for range 5 {
		d = s.nextRetry(d)
		got = append(got, d)
	}
	want := []time.Duration{30 * time.Second, 60 * time.Second, 100 * time.Second, 100 * time.Second, 100 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff = %v, want %v", got, want)
		}
	}

	s.period.Store(int64(10 * time.Second))
	if d := s.nextRetry(0); d != 10*time.Second {
		t.Errorf("first retry with a 10s interval = %s, want 10s", d)
	}
}

func TestCommandStore_Healthy(t *testing.T) {
	s, _ := newTestStore(t, CommandStoreOptions{Interval: 10 * time.Second}, helperSleep)
	s.unit = time.Second
	start := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	clock := start
	s.now = func() time.Time { return clock }
	ctx := context.Background()

	if s.Healthy(ctx) == nil {
		t.Fatal("Healthy before any run must fail")
	}

	s.apply(map[string]string{testCredA: "x"}, -1) // configured 10s interval
	clock = start.Add(20 * time.Second)
	if err := s.Healthy(ctx); err != nil {
		t.Errorf("two intervals after the last success: %v", err)
	}
	clock = start.Add(21 * time.Second)
	if s.Healthy(ctx) == nil {
		t.Error("more than two intervals after the last success must fail")
	}

	clock = start
	s.apply(map[string]string{testCredA: "x"}, 60) // RELOAD_IN=60
	clock = start.Add(119 * time.Second)
	if err := s.Healthy(ctx); err != nil {
		t.Errorf("RELOAD_IN sets the interval for the health check: %v", err)
	}
	clock = start.Add(121 * time.Second)
	if s.Healthy(ctx) == nil {
		t.Error("more than two RELOAD_IN intervals must fail")
	}

	s.apply(map[string]string{testCredA: "x"}, 0) // no further run
	clock = start.Add(1000 * time.Hour)
	if err := s.Healthy(ctx); err != nil {
		t.Errorf("without a further run due the loaded store stays healthy: %v", err)
	}
}

// TestCommandStore_ConcurrentReaders swaps complete sets while readers check
// that every read sees one set, never a mix of two. Run with -race.
func TestCommandStore_ConcurrentReaders(t *testing.T) {
	s, _ := newTestStore(t, CommandStoreOptions{}, helperSleep)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	gen := func(i int) map[string]string {
		v := strconv.Itoa(i)
		return map[string]string{"CREDENTIAL_GEN_A": v, "CREDENTIAL_GEN_B": v, testOther: v}
	}
	s.apply(gen(0), -1)

	ctx := context.Background()
	stop := make(chan struct{})
	errs := make(chan string, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				m, _ := s.ListByPrefix(ctx, "GEN_", TenantInfo{})
				if m["GEN_A"] == "" || m["GEN_A"] != m["GEN_B"] {
					errs <- fmt.Sprintf("mixed or empty set: %q", m)
					return
				}
				if _, err := s.Get(ctx, "gen_a", TenantInfo{}); err != nil {
					errs <- err.Error()
					return
				}
				if v, ok := s.LookupKey(testOther); !ok || v == "" {
					errs <- "OTHER missing"
					return
				}
			}
		}()
	}
	for i := 1; i <= 2000; i++ {
		s.apply(gen(i), -1)
	}
	close(stop)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestCommandStore_ValuesNotInEnvironment(t *testing.T) {
	const (
		key   = "CREDENTIAL_ENVCHECK_TOKEN"
		other = "TOOLMESH_ENVCHECK_SECRET"
	)
	tokenValue := "envcheck-token-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	otherValue := "envcheck-other-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	out := newOutputFile(t, key+"="+tokenValue+"\n"+other+"="+otherValue+"\n")
	s, _ := newTestStore(t, CommandStoreOptions{}, helperPrint, out.path)
	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if v, _ := s.LookupKey(key); v != tokenValue {
		t.Fatalf("store does not hold the value")
	}
	for _, k := range []string{key, other} {
		if _, ok := os.LookupEnv(k); ok {
			t.Errorf("%s is set in the process environment", k)
		}
	}
	for _, kv := range os.Environ() {
		if strings.Contains(kv, tokenValue) || strings.Contains(kv, otherValue) {
			t.Errorf("a store value appears in os.Environ(): %s", strings.SplitN(kv, "=", 2)[0])
		}
	}
}

func TestRemappingStore_ThroughCommandStore(t *testing.T) {
	// The mapped key exists in the environment too; the store must win.
	t.Setenv("GH_PROD_TOKEN", "from-environment")
	out := newOutputFile(t, "CREDENTIAL_GITHUB_TOKEN=direct\nGH_PROD_TOKEN=from-store\n")
	s, _ := newTestStore(t, CommandStoreOptions{}, helperPrint, out.path)
	if err := s.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	r := NewRemappingStore(s, map[string]string{ //nolint:gosec // test credential mapping, not real secrets
		"CREDENTIAL_GITHUB_SECRET": "GH_PROD_TOKEN",
		"CREDENTIAL_GITHUB_ABSENT": "NOT_IN_STORE",
	})
	ctx := context.Background()

	if got, err := r.Get(ctx, "github_secret", TenantInfo{}); err != nil || got != "from-store" {
		t.Errorf("remapped Get = %q, %v; want the store's value", got, err)
	}
	if got, err := r.Get(ctx, "github_token", TenantInfo{}); err != nil || got != "direct" {
		t.Errorf("delegated Get = %q, %v", got, err)
	}
	t.Setenv("NOT_IN_STORE", "from-environment")
	if _, err := r.Get(ctx, "github_absent", TenantInfo{}); err == nil {
		t.Error("a key missing from the store must not fall back to the environment")
	}

	listed, err := r.ListByPrefix(ctx, "GITHUB_", TenantInfo{})
	if err != nil {
		t.Fatalf("ListByPrefix: %v", err)
	}
	if listed["GITHUB_SECRET"] != "from-store" || listed["GITHUB_TOKEN"] != "direct" {
		t.Errorf("ListByPrefix = %q", listed)
	}
	if _, ok := listed["GITHUB_ABSENT"]; ok {
		t.Error("ListByPrefix included a key missing from the store")
	}
}

func TestLookupKey(t *testing.T) {
	t.Setenv("TOOLMESH_LOOKUP_TEST", "from-environment")
	if v, ok := LookupKey(NewEmbeddedStore(), "TOOLMESH_LOOKUP_TEST"); !ok || v != "from-environment" {
		t.Errorf("embedded store: LookupKey = %q, %v; want the environment", v, ok)
	}

	s, _ := newTestStore(t, CommandStoreOptions{}, helperSleep)
	s.apply(map[string]string{testOther: "x"}, -1)
	if _, ok := LookupKey(s, "TOOLMESH_LOOKUP_TEST"); ok {
		t.Error("command store: LookupKey fell back to the environment")
	}
	if v, ok := LookupKey(s, testOther); !ok || v != "x" {
		t.Errorf("command store: LookupKey = %q, %v", v, ok)
	}
}

func TestCommandStoreFactory(t *testing.T) {
	out := newOutputFile(t, "CREDENTIAL_A=from-factory\n")
	cfg := map[string]string{
		CommandConfigCommand:  helperCommand(t, helperPrint, out.path),
		CommandConfigReloadIn: "0",
		CommandConfigTimeout:  "10",
	}
	store, err := New(CommandStoreName, cfg)
	if err != nil {
		t.Fatalf("New(command): %v", err)
	}
	if v, err := store.Get(context.Background(), "a", TenantInfo{}); err != nil || v != "from-factory" {
		t.Errorf("Get = %q, %v", v, err)
	}
	for _, iface := range []struct {
		name string
		ok   bool
	}{
		{"PrefixLister", isA[PrefixLister](store)},
		{"KeyLookup", isA[KeyLookup](store)},
		{"Refresher", isA[Refresher](store)},
	} {
		if !iface.ok {
			t.Errorf("command store does not implement %s", iface.name)
		}
	}

	cfg[CommandConfigCommand] = helperCommand(t, helperFail, testHelperError)
	if _, err := New(CommandStoreName, cfg); err == nil || !strings.Contains(err.Error(), "first run failed") {
		t.Errorf("a failed first run must fail the factory, got %v", err)
	}
}

func isA[T any](v any) bool {
	_, ok := v.(T)
	return ok
}

// TestCommandStore_JSONOutput runs the store on JSON output shaped like
// `vault kv get -format=json`, selected by the path data.data.
func TestCommandStore_JSONOutput(t *testing.T) {
	out := newOutputFile(t, testVaultKV2)
	s, logs := newTestStore(t, CommandStoreOptions{Format: FormatJSON, JSONPath: testPathKV2}, helperPrint, out.path)
	s.unit = time.Second
	ctx := context.Background()
	if err := s.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if v, err := s.Get(ctx, "github_token", TenantInfo{}); err != nil || v != testVaultGH {
		t.Errorf("Get(github_token) = %q, %v", v, err)
	}
	if v, ok := s.LookupKey("TOOLMESH_API_KEY"); !ok || v != testVaultTM {
		t.Errorf("LookupKey(TOOLMESH_API_KEY) = %q, %v", v, ok)
	}
	for _, junk := range []string{"request_id", "lease_duration", "created_time", "version"} {
		if _, ok := s.LookupKey(junk); ok {
			t.Errorf("metadata %s outside the path became a key", junk)
		}
	}
	if p := time.Duration(s.period.Load()); p != 0 {
		t.Errorf("period = %s, want 0: no interval and no RELOAD_IN", p)
	}

	// RELOAD_IN as a JSON number inside the selected object.
	out.set(`{"data": {"data": {"CREDENTIAL_A": "gen2", "RELOAD_IN": 7}}}`)
	if err := s.refresh(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := getA(s); got != testGen2 {
		t.Errorf("CREDENTIAL_A = %q, want %q", got, testGen2)
	}
	if p := time.Duration(s.period.Load()); p != 7*time.Second {
		t.Errorf("period = %s, want RELOAD_IN 7s", p)
	}
	if _, ok := s.LookupKey(ReloadInKey); ok {
		t.Error("RELOAD_IN must not be stored as a value")
	}

	// Broken JSON fails the run and keeps the set.
	out.set(`{"data": {"data": {"CREDENTIAL_A": "gen3"`)
	if err := s.refresh(ctx); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("refresh with broken JSON: %v", err)
	}
	if got := getA(s); got != testGen2 {
		t.Errorf("after a failed run CREDENTIAL_A = %q, want the previous %q", got, testGen2)
	}
	for _, secret := range []string{testVaultGH, testVaultTM, "deepl-from-vault"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("log contains the value %q", secret)
		}
	}
}

func TestParseCommandStoreConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     map[string]string
		want    CommandStoreOptions
		wantErr string
	}{
		{name: "defaults", cfg: map[string]string{CommandConfigCommand: "/bin/tool"},
			want: CommandStoreOptions{Command: "/bin/tool", Timeout: DefaultCommandTimeout}},
		{name: "all set", cfg: map[string]string{CommandConfigCommand: " /bin/tool -x ", CommandConfigReloadIn: "300", CommandConfigTimeout: "5"},
			want: CommandStoreOptions{Command: "/bin/tool -x", Interval: 300 * time.Second, Timeout: 5 * time.Second}},
		{name: "no command", cfg: map[string]string{}, wantErr: "no command configured"},
		{name: "reload not a number", cfg: map[string]string{CommandConfigCommand: "x", CommandConfigReloadIn: "5m"}, wantErr: "TOOLMESH_CREDENTIAL_RELOAD_IN"},
		{name: "negative reload", cfg: map[string]string{CommandConfigCommand: "x", CommandConfigReloadIn: "-1"}, wantErr: "TOOLMESH_CREDENTIAL_RELOAD_IN"},
		{name: "timeout zero", cfg: map[string]string{CommandConfigCommand: "x", CommandConfigTimeout: "0"}, wantErr: "at least one second"},
		{name: "timeout not a number", cfg: map[string]string{CommandConfigCommand: "x", CommandConfigTimeout: "ten"}, wantErr: "TOOLMESH_CREDENTIAL_COMMAND_TIMEOUT"},
		{name: "json with path", cfg: map[string]string{CommandConfigCommand: "x", CommandConfigFormat: " json ", CommandConfigJSONPath: " data.data "},
			want: CommandStoreOptions{Command: "x", Timeout: DefaultCommandTimeout, Format: FormatJSON, JSONPath: testPathKV2}},
		{name: "unknown format", cfg: map[string]string{CommandConfigCommand: "x", CommandConfigFormat: "yaml"}, wantErr: "TOOLMESH_CREDENTIAL_FORMAT must be"},
		{name: "json path without json", cfg: map[string]string{CommandConfigCommand: "x", CommandConfigJSONPath: testDataKey}, wantErr: "TOOLMESH_CREDENTIAL_JSON_PATH"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCommandStoreConfig(tt.cfg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCommandStoreConfig: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}

	if _, err := New(CommandStoreName, map[string]string{CommandConfigCommand: "sops -d f | cat"}); err == nil || !strings.Contains(err.Error(), "without a shell") {
		t.Errorf("shell syntax must be refused at startup, got %v", err)
	}
}
