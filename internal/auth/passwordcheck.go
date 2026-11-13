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

package auth

import "time"

// Outcomes of a password login (PasswordCheck.Outcome).
const (
	// PasswordOK: the password is the user's.
	PasswordOK = "ok"
	// PasswordInvalid: unknown user or wrong password; the two are not
	// told apart.
	PasswordInvalid = "invalid"
	// PasswordThrottled: too many failed logins; the password was not
	// looked at.
	PasswordThrottled = "throttled"
	// PasswordBusy: no comparison could be started; the attempt counts as
	// neither failed nor successful.
	PasswordBusy = "busy"
	// PasswordDisabled: this ToolMesh has no password login.
	PasswordDisabled = "disabled"
)

// PasswordCheck is the result of checking a submitted username and password
// against the configured identities.
type PasswordCheck struct {
	Outcome string
	// The identity that signed in; set for PasswordOK only.
	UserID    string
	CompanyID string
	Plan      string
	Roles     []string
	// Fingerprint identifies the password that was accepted without
	// revealing it. It changes when the password does, which ends what was
	// issued on the old one.
	Fingerprint string
	// RetryAfter is how long the limit that blocked the attempt still
	// runs; set for PasswordThrottled only.
	RetryAfter time.Duration
}
