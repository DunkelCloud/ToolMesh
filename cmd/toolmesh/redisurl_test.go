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

package main

import (
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestRedisURLError_DropsPassword(t *testing.T) {
	const password = "redis-url-password" //nolint:gosec // test fixture, not a credential
	for _, raw := range []string{
		"redis://:" + password + "@keydb:63x79/0", // invalid port
		"redis://:" + password + "@key db:6379/0", // invalid host
		"ftp://:" + password + "@keydb:6379/0",    // invalid scheme
	} {
		_, err := redis.ParseURL(raw)
		if err == nil {
			t.Fatalf("expected %q not to parse", strings.ReplaceAll(raw, password, "***"))
		}
		if got := redisURLError(err); got == nil || strings.Contains(got.Error(), password) {
			t.Errorf("logged error %v carries the password", got)
		}
	}
}
