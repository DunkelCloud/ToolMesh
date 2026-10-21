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

package gate

import (
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	testPolicyLimit   = "limit.js"
	testReasonLimit   = "limited"
	testUserPreflight = "preflight-user"
)

// TestGate_Evaluate_PreflightNotRecorded: a preflight is not a call, so it
// does not count for rate limiting; and the pipeline reports a refusal as a
// Rejection that names the evaluator, the policy and the reason.
func TestGate_Evaluate_PreflightNotRecorded(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, testPolicyLimit, `if (ctx.rateLimitExceeded(1)) { throw "`+testReasonLimit+`"; }`)
	g, err := New(dir, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p := NewPipeline([]Evaluator{g})
	call := GateContext{User: userctx.UserContext{UserID: testUserPreflight}, Tool: testToolName, Params: map[string]any{}}
	preflight := call
	preflight.Preflight = true

	for i := range 3 {
		if _, err := p.EvaluatePre(preflight); err != nil {
			t.Fatalf("preflight %d: %v, want it to pass: nothing was called yet", i+1, err)
		}
	}
	if _, err := p.EvaluatePre(call); err != nil {
		t.Fatalf("first call: %v, want it to pass: the preflights were not recorded", err)
	}
	_, err = p.EvaluatePre(call)
	var rej *Rejection
	if !errors.As(err, &rej) || rej.Evaluator != "goja" || rej.Policy != testPolicyLimit || rej.Reason != "policy "+testPolicyLimit+": "+testReasonLimit {
		t.Fatalf("second call: %v, want a Rejection by %s", err, testPolicyLimit)
	}
	if want := "evaluator goja rejected: policy " + testPolicyLimit + ": " + testReasonLimit; err.Error() != want {
		t.Errorf("error text = %q, want %q", err.Error(), want)
	}
}
