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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// HintAccessAll is the hint_required_for entry that matches every tool of a
// backend, including tools without an access classification.
const HintAccessAll = "all"

// MetadataKeyHintRequired marks a ToolResult as the refusal of a call that
// lacked a current hint proof. Its value is the name of the backend whose
// hint the result carries.
const MetadataKeyHintRequired = "hint_required"

// hintProofDigestLen is the number of hex characters of the digest a hint
// proof carries. 64 bits are far more than a caller can guess and short
// enough to copy without error.
const hintProofDigestLen = 16

// HintRequired reports whether a call to a tool with the given access
// classification runs only for a caller that shows it has received the
// backend's hint (backends.yaml hint_required_for). A backend without a hint
// never requires one: there would be nothing to deliver.
func (i BackendInfo) HintRequired(access string) bool {
	if strings.TrimSpace(i.Hint) == "" {
		return false
	}
	for _, class := range i.HintRequiredFor {
		if class == HintAccessAll {
			return true
		}
		if access != "" && strings.EqualFold(class, access) {
			return true
		}
	}
	return false
}

// HintProof returns the proof that a caller has received a backend's hint on
// the given day: "<backend>:<digest>", the digest taken over the backend
// name, the hint text and the UTC date.
//
// The proof answers one question: was the hint delivered to this
// conversation, in its present wording, today? A gateway cannot tell
// conversations apart, so it cannot remember the answer; the caller carries
// it instead and hands it back with the call. The date makes every proof
// expire at the end of the day, so a proof copied into an instruction file
// or carried through a long conversation stops working and the hint is
// delivered again. A changed hint invalidates the proof at once.
//
// The digest is not keyed and is no access control. Whoever can compute it
// has the hint text, which is all it is meant to show; who may call a tool
// is decided by authorization. Without a key the proof holds across
// restarts and across instances behind one address.
func HintProof(backendName, hint string, day time.Time) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		backendName,
		strings.TrimSpace(hint),
		day.UTC().Format(time.DateOnly),
	}, "\x00")))
	return backendName + ":" + hex.EncodeToString(sum[:])[:hintProofDigestLen]
}

// HintProofBackend returns the backend name of a proof in the form
// HintProof returns, or false when the text is not of that form.
func HintProofBackend(proof string) (string, bool) {
	i := strings.LastIndex(proof, ":")
	if i <= 0 || i == len(proof)-1 {
		return "", false
	}
	return proof[:i], true
}

// validateHintRequiredFor rejects a backends.yaml entry that requires a hint
// it does not have. Such an entry would look protected and deliver nothing.
func validateHintRequiredFor(entry BackendEntry) error {
	if len(entry.HintRequiredFor) == 0 {
		return nil
	}
	if strings.TrimSpace(entry.Hint) == "" {
		return fmt.Errorf("backend %q: hint_required_for is set but hint is empty", entry.Name)
	}
	for _, class := range entry.HintRequiredFor {
		if strings.TrimSpace(class) == "" {
			return fmt.Errorf("backend %q: hint_required_for has an empty entry", entry.Name)
		}
	}
	return nil
}
