// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import "fmt"

type sessionOptions struct {
	EnableInterleaving bool
	MaxMessageSize     uint32
}

func supportLabel(adapter Adapter, ok bool) string {
	name := "unknown"
	if adapter != nil {
		if got := adapter.Name(); got != "" {
			name = got
		}
	}
	status := "unsupported"
	if ok {
		status = "supported"
	}

	return fmt.Sprintf("%s(%s)", name, status)
}
