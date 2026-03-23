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

import "context"

type credKey struct{}

// WithCredentials stores credentials in the context for downstream use.
func WithCredentials(ctx context.Context, creds map[string]string) context.Context {
	return context.WithValue(ctx, credKey{}, creds)
}

// CredentialsFromContext extracts credentials from the context.
func CredentialsFromContext(ctx context.Context) map[string]string {
	creds, _ := ctx.Value(credKey{}).(map[string]string)
	return creds
}
