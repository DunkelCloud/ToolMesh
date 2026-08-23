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

package dadl

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Byte-size unit multipliers. KB/MB/GB are 1024-based, not 1000-based.
//
// The SI reading would be defensible in isolation, but not here: this runtime
// writes its own ceilings as `100 * 1024 * 1024 // 100 MB`, and a tool
// declaring `max_body_size: 100MB` against a 100 MiB ceiling must land exactly
// on it rather than 4.8% under it for reasons no DADL author could see. The
// IEC spellings are accepted as explicit synonyms for authors who want the
// base stated rather than assumed.
const (
	byteSizeKB = 1024
	byteSizeMB = 1024 * byteSizeKB
	byteSizeGB = 1024 * byteSizeMB
)

// byteSizeUnits maps an upper-cased unit suffix to its multiplier. The empty
// suffix is a bare byte count.
var byteSizeUnits = map[string]int64{
	"":    1,
	"B":   1,
	"K":   byteSizeKB,
	"KB":  byteSizeKB,
	"KIB": byteSizeKB,
	"M":   byteSizeMB,
	"MB":  byteSizeMB,
	"MIB": byteSizeMB,
	"G":   byteSizeGB,
	"GB":  byteSizeGB,
	"GIB": byteSizeGB,
}

// ParseByteSize converts a DADL size string into a byte count. Accepted forms
// are a number, optional whitespace, and an optional unit — "50MB",
// "128 KiB", "1.5 GB", "1048576" — with the unit matched case-insensitively.
//
// It is deliberately strict about what it will not read. A size that cannot
// be parsed is an error rather than a fallback, because every fallback here
// is a wider limit than the author wrote: silently reading an unparseable
// `max_body_size` as "no limit declared" would turn a typo into a lifted cap,
// which is the failure the field exists to prevent. Zero and negative sizes
// are rejected on the same grounds — a cap of zero bytes admits nothing and is
// far more likely a mistake than an intent.
func ParseByteSize(s string) (int64, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, fmt.Errorf("empty size")
	}

	// Split at the first character that cannot belong to the number.
	split := len(trimmed)
	for i, r := range trimmed {
		if (r < '0' || r > '9') && r != '.' {
			split = i
			break
		}
	}
	digits := trimmed[:split]
	unit := strings.ToUpper(strings.TrimSpace(trimmed[split:]))

	multiplier, ok := byteSizeUnits[unit]
	if !ok {
		return 0, fmt.Errorf("unknown unit %q in size %q (use B, KB, MB, GB, or the KiB/MiB/GiB spellings)", unit, s)
	}

	value, err := strconv.ParseFloat(digits, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("invalid size %q: must be greater than zero", s)
	}

	bytes := value * float64(multiplier)
	if bytes > math.MaxInt64 {
		return 0, fmt.Errorf("invalid size %q: exceeds the maximum representable byte count", s)
	}
	return int64(bytes), nil
}

// FormatByteSize renders a byte count in the same vocabulary ParseByteSize
// reads, so a message about a limit echoes the spelling an author would
// recognize. Values that are not whole multiples fall back to the exact byte
// count rather than rounding — a limit message that rounds is a limit message
// that misleads.
func FormatByteSize(n int64) string {
	switch {
	case n >= byteSizeGB && n%byteSizeGB == 0:
		return strconv.FormatInt(n/byteSizeGB, 10) + "GB"
	case n >= byteSizeMB && n%byteSizeMB == 0:
		return strconv.FormatInt(n/byteSizeMB, 10) + "MB"
	case n >= byteSizeKB && n%byteSizeKB == 0:
		return strconv.FormatInt(n/byteSizeKB, 10) + "KB"
	default:
		return strconv.FormatInt(n, 10) + " bytes"
	}
}
