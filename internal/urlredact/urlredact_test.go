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

package urlredact

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestText(t *testing.T) {
	cases := []struct{ in, want string }{
		{`Get "https://api.example.com/v1/x?api_key=SECRET": EOF`, `Get "https://api.example.com/v1/x": EOF`},
		{"see https://u:p@h.example/p#frag now", "see https://h.example/p now"},
		{"plain https://h.example/p stays", "plain https://h.example/p stays"},
		{"no url here", "no url here"},
	}
	for _, c := range cases {
		if got := Text(c.in); got != c.want {
			t.Errorf("Text(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTransportErrorAndURLErrors(t *testing.T) {
	inner := &url.Error{Op: "Post", URL: "https://auth.example/token?client_secret=SECRET", Err: context.DeadlineExceeded}
	got := TransportError(fmt.Errorf("wrapped: %w", inner))
	if strings.Contains(got.Error(), "SECRET") || !errors.Is(got, context.DeadlineExceeded) {
		t.Errorf("TransportError = %v", got)
	}
	if strings.Contains(URLErrors(fmt.Errorf("x: %w", inner)).Error(), "SECRET") {
		t.Error("URLErrors leaked the query")
	}
}
