// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"context"
	"strings"
	"time"
)

const (
	caseMaxBurst            = "max-burst"
	caseHandshake           = "handshake"
	caseUnorderedLowRTT     = "unordered-late-low-rtt"
	caseUnorderedHighRTT    = "unordered-late-high-rtt"
	caseUnorderedDynamicRTT = "unordered-late-dynamic-rtt"
	caseCongestionRack      = "congestion"
	caseRetransmission      = "retransmission"
	caseRackReorderLow      = "reorder-low"
	caseRackReorderHigh     = "reorder-high"
	caseRackBurstLoss       = "burst-loss"
	caseFragmentation       = "fragmentation"
	caseInterleaving        = "interleaving"
	caseMediaHEVC           = "media-hevc"
	caseFaultChecksum       = "fault-checksum"
	caseFaultBadChunkLen    = "fault-bad-chunk-len"
	caseFaultNonZeroPadding = "fault-nonzero-padding"
)

type scenarioResult struct {
	CaseName     string
	Pair         pair
	Profile      networkProfile
	ForwardBurst int
	ReverseBurst int
	Passed       bool
	Errored      bool
	Details      string
	WireLog      string
	Iteration    int
	Metrics      resultMetrics
}

func runCases(ctx context.Context, caseNames []string, pairs []pair, seed int64, repeat int, timeout time.Duration, outDir string, interleavingOverride string) ([]scenarioResult, error) {
	names := resolveCaseNames(caseNames)
	if len(names) == 0 {
		return nil, errNoCases
	}
	resolvedSeed := resolveSeed(seed)

	var results []scenarioResult
	for _, name := range names {
		def, err := caseDefinitionFor(name)
		if err != nil {
			return nil, err
		}
		res, err := runCase(ctx, pairs, resolvedSeed, repeat, timeout, outDir, def, interleavingOverride)
		if err != nil {
			return nil, err
		}
		results = append(results, res...)
	}

	return results, nil
}

func resolveCaseNames(names []string) []string {
	normalized := normalizeCases(names)
	if len(normalized) == 0 {
		return []string{caseMaxBurst}
	}

	return normalized
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
