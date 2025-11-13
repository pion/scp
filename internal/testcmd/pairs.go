// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pion/scp/internal/scp"
)

type pair struct {
	Left  scp.LockEntry
	Right scp.LockEntry
}

func buildNameSet(values []string) map[string]struct{} {
	names := scp.SplitAndTrim(values)
	if len(names) == 0 {
		return nil
	}

	result := make(map[string]struct{}, len(names))
	for _, name := range names {
		result[name] = struct{}{}
	}

	return result
}

func selectEntries(entries []scp.LockEntry, include, exclude map[string]struct{}) ([]scp.LockEntry, error) {
	if len(entries) == 0 {
		return nil, errEmptyLock
	}
	if err := ensureIncluded(entries, include); err != nil {
		return nil, err
	}

	var filtered []scp.LockEntry
	for _, entry := range entries {
		if len(include) > 0 {
			if _, ok := include[entry.Name]; !ok {
				continue
			}
		}
		if len(exclude) > 0 {
			if _, ok := exclude[entry.Name]; ok {
				continue
			}
		}
		filtered = append(filtered, entry)
	}

	if len(filtered) == 0 {
		return nil, errNoSelectableEntries
	}

	return filtered, nil
}

func ensureIncluded(entries []scp.LockEntry, include map[string]struct{}) error {
	if len(include) == 0 {
		return nil
	}

	present := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		present[entry.Name] = struct{}{}
	}

	var missing []string
	for name := range include {
		if _, ok := present[name]; !ok {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%w: %s", errRequestedEntryMissing, strings.Join(missing, ", "))
	}

	return nil
}

func buildPairs(entries []scp.LockEntry, mode string, explicit []string) ([]pair, error) {
	if len(entries) == 0 {
		return nil, errEmptyLock
	}
	if len(entries) < 2 && mode != "self" && mode != "explicit" {
		return nil, errInsufficientEntries
	}

	switch mode {
	case "", DefaultPairMode:
		return adjacentPairs(entries), nil
	case "latest-prev":
		return latestPrevPair(entries), nil
	case "matrix":
		return matrixPairs(entries), nil
	case "explicit":
		return explicitPairs(entries, explicit)
	case "self":
		return selfPairs(entries), nil
	default:
		return nil, fmt.Errorf("%w: %s", errUnknownPairMode, mode)
	}
}

func adjacentPairs(entries []scp.LockEntry) []pair {
	pairs := make([]pair, 0, len(entries)-1)
	for i := 1; i < len(entries); i++ {
		pairs = append(pairs, pair{Left: entries[i-1], Right: entries[i]})
	}

	return pairs
}

func latestPrevPair(entries []scp.LockEntry) []pair {
	last := len(entries) - 1

	return []pair{{Left: entries[last-1], Right: entries[last]}}
}

func matrixPairs(entries []scp.LockEntry) []pair {
	estimated := len(entries) * (len(entries) - 1) / 2
	pairs := make([]pair, 0, estimated)
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			pairs = append(pairs, pair{Left: entries[i], Right: entries[j]})
		}
	}

	return pairs
}

func explicitPairs(entries []scp.LockEntry, specs []string) ([]pair, error) {
	flattened := scp.SplitAndTrim(specs)
	if len(flattened) == 0 {
		return nil, errMissingExplicitPairs
	}

	lookup := make(map[string]scp.LockEntry, len(entries))
	for _, entry := range entries {
		lookup[entry.Name] = entry
	}

	pairs := make([]pair, 0, len(flattened))
	for _, spec := range flattened {
		parts := strings.SplitN(spec, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("%w: %s", errMissingExplicitPairs, spec)
		}
		left, ok := lookup[parts[0]]
		if !ok {
			return nil, fmt.Errorf("%w: %s", errRequestedEntryMissing, parts[0])
		}
		right, ok := lookup[parts[1]]
		if !ok {
			return nil, fmt.Errorf("%w: %s", errRequestedEntryMissing, parts[1])
		}
		pairs = append(pairs, pair{Left: left, Right: right})
	}

	return pairs, nil
}

func selfPairs(entries []scp.LockEntry) []pair {
	pairs := make([]pair, 0, len(entries))
	for _, entry := range entries {
		pairs = append(pairs, pair{Left: entry, Right: entry})
	}

	return pairs
}
