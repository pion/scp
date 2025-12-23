// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import "fmt"

const (
	interleavingAuto = "auto"
	interleavingOn   = "on"
	interleavingOff  = "off"
)

type interleavingSupport interface {
	SupportsInterleaving() bool
}

func supportsInterleaving(adapter Adapter) bool {
	if adapter == nil {
		return false
	}
	if cap, ok := adapter.(interleavingSupport); ok {
		return cap.SupportsInterleaving()
	}

	return false
}

func validateInterleavingOverride(mode string) error {
	switch mode {
	case "", interleavingAuto, interleavingOn, interleavingOff:
		return nil
	default:
		return fmt.Errorf("%w: %s", errInvalidInterleaving, mode)
	}
}

func resolveInterleaving(def caseDefinition, override string) bool {
	switch override {
	case interleavingOn:
		return true
	case interleavingOff:
		return false
	default:
		return def.EnableInterleaving
	}
}
