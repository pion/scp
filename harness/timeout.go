// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"fmt"
	"strings"
	"time"
)

func parseTimeout(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = DefaultTimeout
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%w: %s", errInvalidTimeout, raw)
	}

	return parsed, nil
}
