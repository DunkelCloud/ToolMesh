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

// Package urlredact removes request URLs, and with them query-injected
// credentials, from error texts before they reach logs, the audit trail or a
// tool result.
package urlredact

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Origin reduces a raw URL to scheme://host, dropping userinfo, path,
// query and fragment. Unparsable input yields a fixed placeholder.
func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(url omitted)"
	}
	return u.Scheme + "://" + u.Host
}

// transportError is a *url.Error rendered without the request URL's path and
// query. It unwraps to the transport cause, so errors.Is checks such as
// context.DeadlineExceeded keep working.
type transportError struct {
	op     string
	origin string
	err    error
}

// Error implements error.
func (e *transportError) Error() string {
	return fmt.Sprintf("%s %s: %v", e.op, e.origin, e.err)
}

// Unwrap returns the transport cause.
func (e *transportError) Unwrap() error { return e.err }

// Timeout reports whether the cause is a timeout, like (*url.Error).Timeout.
func (e *transportError) Timeout() bool {
	var t interface{ Timeout() bool }
	return errors.As(e.err, &t) && t.Timeout()
}

// TransportError converts a *url.Error returned by an HTTP client into
// a transportError that names only scheme and host. A request URL can carry a
// query-injected API key (auth.inject_into: query), and the error text reaches
// the audit log and, through tool results, the model. Other errors pass
// through unchanged.
func TransportError(err error) error {
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err
	}
	return &transportError{op: urlErr.Op, origin: Origin(urlErr.URL), err: urlErr.Err}
}

// redactedText is an error whose message was rewritten; it still unwraps to
// the original error.
type redactedText struct {
	text string
	err  error
}

// Error implements error.
func (e *redactedText) Error() string { return e.text }

// Unwrap returns the original error.
func (e *redactedText) Unwrap() error { return e.err }

// URLErrors returns an error equivalent to err whose message shows the
// URL of every *url.Error in its chain reduced to scheme://host. It is the
// last line of defense before an error text is written to the audit log or
// returned to a caller, for backends that do not redact at the call site.
func URLErrors(err error) error {
	if err == nil {
		return nil
	}
	text := err.Error()
	changed := false
	stack := []error{err}
	for len(stack) > 0 {
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if e == nil {
			continue
		}
		if ue, ok := e.(*url.Error); ok && ue.URL != "" { //nolint:errorlint // the loop walks the chain one level at a time
			origin := Origin(ue.URL)
			for _, form := range []string{strconv.Quote(ue.URL), ue.URL} {
				if strings.Contains(text, form) {
					text = strings.ReplaceAll(text, form, origin)
					changed = true
				}
			}
		}
		switch u := e.(type) { //nolint:errorlint // inspects this level's Unwrap method, not a wrapped error
		case interface{ Unwrap() error }:
			stack = append(stack, u.Unwrap())
		case interface{ Unwrap() []error }:
			stack = append(stack, u.Unwrap()...)
		}
	}
	if !changed {
		return err
	}
	return &redactedText{text: text, err: err}
}

// urlInText matches http(s) URLs inside free text, up to the first
// whitespace, quote or angle bracket.
var urlInText = regexp.MustCompile("(?i)\\bhttps?://[^\\s\"'<>`]+")

// Text returns s with the userinfo, query and fragment removed from every
// http(s) URL in it. It is meant for error texts whose structure is gone,
// such as a tool result built from an error: a query-injected credential in
// a request URL must not reach the model or the audit log. Paths stay, so
// the text still says which endpoint failed.
func Text(s string) string {
	return urlInText.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return raw
		}
		if u.User == nil && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery {
			return raw
		}
		return u.Scheme + "://" + u.Host + u.EscapedPath()
	})
}
