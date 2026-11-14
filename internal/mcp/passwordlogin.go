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

package mcp

import (
	"net/http"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// checkPassword checks a submitted username and password against users.yaml
// or the single configured password. It is the one place a password is
// compared, for the login form of /authorize and for every other page that
// signs a user in, so all of them share the failed-login limits, the bound
// on password comparisons and the log lines.
//
// The attempt reserves a slot against the failed-login limits before the
// password is looked at. In single-password mode the submitted username is
// not part of the credential, so every attempt counts against the one
// configured account: typing a different name must not start a fresh count.
// The caller makes sure a password login is configured.
func (s *Server) checkPassword(r *http.Request, username, password string) auth.PasswordCheck {
	account := username
	if s.userStore == nil {
		account = s.cfg.AuthUser
	}
	attempt := s.loginThrottle.Acquire(r.Context(), account, auth.ClientIP(r))
	if !attempt.Allowed {
		s.loginFailed(r, username, loginReasonThrottledPrefix+attempt.Scope)
		return auth.PasswordCheck{Outcome: auth.PasswordThrottled, RetryAfter: attempt.RetryAfter}
	}

	var check auth.PasswordCheck
	if s.userStore != nil {
		// Multi-user mode (users.yaml)
		user, err := s.userStore.Authenticate(r.Context(), username, password)
		if err != nil {
			// The password was not checked. The attempt is neither a failed
			// login nor a successful one, so its slot goes back unused.
			s.loginThrottle.Cancel(r.Context(), attempt)
			s.compareDeferred(r, loginMethodPassword, err)
			return auth.PasswordCheck{Outcome: auth.PasswordBusy}
		}
		if user == nil {
			s.loginFailed(r, username, loginReasonInvalidCredentials)
			return auth.PasswordCheck{Outcome: auth.PasswordInvalid}
		}
		check = auth.PasswordCheck{
			Outcome:     auth.PasswordOK,
			UserID:      user.Username,
			CompanyID:   user.Company,
			Plan:        user.Plan,
			Roles:       user.Roles,
			Fingerprint: hashFingerprint(user.PasswordHash),
		}
	} else {
		// Legacy single-password mode
		if !secretsEqual(password, s.cfg.AuthPassword) {
			s.loginFailed(r, username, loginReasonInvalidCredentials)
			return auth.PasswordCheck{Outcome: auth.PasswordInvalid}
		}
		check = auth.PasswordCheck{
			Outcome:     auth.PasswordOK,
			UserID:      s.cfg.AuthUser,
			CompanyID:   userDefault,
			Plan:        s.cfg.AuthPlan,
			Roles:       s.cfg.AuthRolesList(),
			Fingerprint: s.ownerFingerprint(),
		}
	}

	// The password was right, whatever the caller does with the login.
	s.loginThrottle.Success(r.Context(), attempt)
	return check
}

// PasswordLoginEnabled reports whether this ToolMesh has a password login:
// users.yaml is loaded or a single password is set.
func (s *Server) PasswordLoginEnabled() bool {
	return s.passwordLoginConfigured()
}

// PasswordLogin signs a user in with username and password for a page of
// this ToolMesh other than /authorize. It applies the same failed-login
// limits and writes the same log lines and metrics as the login there.
func (s *Server) PasswordLogin(r *http.Request, username, password string) auth.PasswordCheck {
	if !s.passwordLoginConfigured() {
		s.loginRejected(r, username, loginReasonPasswordLoginDisabled)
		return auth.PasswordCheck{Outcome: auth.PasswordDisabled}
	}
	check := s.checkPassword(r, username, password)
	if check.Outcome == auth.PasswordOK {
		s.metrics.RecordLogin(loginMethodPassword, "success")
	}
	return check
}

// UserIdentity returns the identity userID has now, for pages of this
// ToolMesh that act for a signed-in user: company, plan and roles as a
// token issued to that user today would carry them. It returns false when
// the user no longer exists or there is no password login.
func (s *Server) UserIdentity(userID string) (*userctx.UserContext, bool) {
	id, ok := s.currentIdentity(userID)
	if !ok {
		return nil, false
	}
	return &userctx.UserContext{
		UserID:        userID,
		CompanyID:     id.companyID,
		Plan:          id.plan,
		Roles:         id.roles,
		Authenticated: true,
	}, true
}

// PasswordFingerprint returns the fingerprint of the password userID signs
// in with now, and false when the user no longer exists or there is no
// password login. A session compares it with the fingerprint of its login:
// a changed password ends the session.
func (s *Server) PasswordFingerprint(userID string) (string, bool) {
	id, ok := s.currentIdentity(userID)
	if !ok {
		return "", false
	}
	return id.fp, true
}
