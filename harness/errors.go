// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package harness provides the scaffolding for the scp test command.
package harness

import "errors"

var (
	errMissingLockPath         = errors.New("test: lock path is required")
	errEmptyLock               = errors.New("test: lock file has no entries")
	errNoSelectableEntries     = errors.New("test: no entries selected after filtering")
	errRequestedEntryMissing   = errors.New("test: requested entry missing")
	errNoCases                 = errors.New("test: no cases specified")
	errInsufficientEntries     = errors.New("test: at least two entries are required")
	errUnknownPairMode         = errors.New("test: unknown pair mode")
	errMissingExplicitPairs    = errors.New("test: explicit pairs required")
	errUnknownCase             = errors.New("test: unknown scenario case")
	errInvalidRepeat           = errors.New("test: repeat must be >= 1")
	errInvalidTimeout          = errors.New("test: timeout must be a valid duration")
	errInvalidInterleaving     = errors.New("test: invalid interleaving override")
	errMissingAdapter          = errors.New("test: missing adapter for entry")
	errInterleavingUnsupported = errors.New("test: interleaving not supported by adapter")
	errScenarioFailed          = errors.New("test: scenario failed")
)
