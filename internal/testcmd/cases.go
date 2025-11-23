// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"context"
	"fmt"
	"strings"
)

const (
	caseMaxBurst = "max-burst"
)

type scenarioResult struct {
	CaseName     string
	Pair         pair
	ForwardBurst int
	ReverseBurst int
	Passed       bool
	Details      string
	Iteration    int
	Metrics      resultMetrics
}

func runCases(ctx context.Context, caseNames []string, pairs []pair, seed int64, repeat int) ([]scenarioResult, error) {
	names := normalizeCases(caseNames)
	if len(names) == 0 {
		return nil, errNoCases
	}

	var results []scenarioResult
	for _, name := range names {
		switch name {
		case caseMaxBurst:
			res, err := runMaxBurstCase(ctx, pairs, seed, repeat)
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		default:
			return nil, fmt.Errorf("%w: %s", errUnknownCase, name)
		}
	}

	return results, nil
}

func normalizeCases(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	var ordered []string
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		ordered = append(ordered, trimmed)
	}

	return ordered
}
