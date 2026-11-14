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

package authz

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

// TestEmbedded_CloseWhileChecksRun closes the engine while checks are in
// flight (even rounds) and right after the last one returned (odd rounds).
//
// OpenFGA answers a check as soon as the result is known and lets the
// remaining workers of that check finish on their own. A worker that then
// stopped its tuple iterator added a goroutine to a wait group the server's
// Close was already waiting on, and Close panicked with "sync: WaitGroup is
// reused before previous Wait has returned". Close now ends the server's
// context first, which keeps the workers from adding anything.
//
// The panic never showed on every close, so a pass of these few rounds proves
// little. To measure, loop the test:
//
//	go test -run TestEmbedded_CloseWhileChecksRun -count=100 ./internal/authz
//
// A check that overlaps Close may fail. Once Close has returned, a check must
// fail: the engine never allows a call it can no longer decide.
func TestEmbedded_CloseWhileChecksRun(t *testing.T) {
	const rounds, checkers = 4, 8
	ctx := context.Background()
	for round := range rounds {
		e, err := OpenEmbedded(ctx, EmbeddedOptions{Path: filepath.Join(t.TempDir(), DBFileName)})
		if err != nil {
			t.Fatalf("round %d: OpenEmbedded: %v", round, err)
		}
		if _, err := e.Apply(ctx,
			[]Grant{{User: testOwner, AllTools: true}, {User: testBob, Backends: []string{testGitHub}}},
			[]Grant{{User: testCarol, Tools: []string{testGitHubListRepos}}},
		); err != nil {
			t.Fatalf("round %d: Apply: %v", round, err)
		}

		var wg sync.WaitGroup
		stop := make(chan struct{})
		warm := make(chan struct{}, checkers)
		for c := range checkers {
			wg.Go(func() {
				users := []string{testOwner, testBob, testCarol}
				for n := 0; ; n++ {
					select {
					case <-stop:
						return
					default:
					}
					// A tool of its own per check keeps OpenFGA's iterator
					// cache cold, so every check reads the store.
					tool := testGitHub + "_c" + strconv.Itoa(c) + "_" + strconv.Itoa(n)
					_, _ = e.Check(ctx, Request{UserID: users[n%len(users)], Tool: tool, Backend: testGitHub, Access: testWrite})
					if n == 2 {
						warm <- struct{}{}
					}
				}
			})
		}
		for range checkers {
			<-warm
		}
		inFlight := round%2 == 0
		if !inFlight {
			close(stop)
			wg.Wait()
		}
		if err := e.Close(); err != nil {
			t.Errorf("round %d: Close: %v", round, err)
		}
		if inFlight {
			close(stop)
			wg.Wait()
		}

		allowed, err := e.Check(ctx, Request{UserID: testOwner, Tool: testGitHubListRepos, Backend: testGitHub})
		if allowed || err == nil {
			t.Errorf("round %d: check after Close = %v, %v; want it to fail", round, allowed, err)
		}
		if err := e.Close(); err != nil {
			t.Errorf("round %d: second Close: %v", round, err)
		}
	}
}
