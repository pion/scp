// Package testcmd provides the scaffolding for the scp test command.
package testcmd

import "errors"

var (
	errMissingLockPath       = errors.New("test: lock path is required")
	errEmptyLock             = errors.New("test: lock file has no entries")
	errNoSelectableEntries   = errors.New("test: no entries selected after filtering")
	errRequestedEntryMissing = errors.New("test: requested entry missing")
	errInsufficientEntries   = errors.New("test: at least two entries are required")
	errUnknownPairMode       = errors.New("test: unknown pair mode")
	errMissingExplicitPairs  = errors.New("test: explicit pairs required")
	errUnknownCase           = errors.New("test: unknown scenario case")
	errInvalidRepeat         = errors.New("test: repeat must be >= 1")
	errScenarioFailed        = errors.New("test: scenario failed")
)
