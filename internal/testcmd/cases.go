// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"context"
	"fmt"
	"strings"
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
)

type scenarioResult struct {
	CaseName     string
	Pair         pair
	ForwardBurst int
	ReverseBurst int
	Passed       bool
	Errored      bool
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
		case caseHandshake:
			res, err := runHandshakeCase(ctx, pairs, seed, repeat)
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		case caseUnorderedLowRTT:
			res, err := runUnorderedCase(ctx, pairs, seed, repeat, lowRTTProfile())
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		case caseUnorderedHighRTT:
			res, err := runUnorderedCase(ctx, pairs, seed, repeat, highRTTProfile())
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		case caseUnorderedDynamicRTT:
			res, err := runUnorderedCase(ctx, pairs, seed, repeat, dynamicRTTProfile())
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		case caseCongestionRack:
			res, err := runCongestionCase(ctx, pairs, seed, repeat)
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		case caseRetransmission:
			res, err := runRetransmissionCase(ctx, pairs, seed, repeat)
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		case caseRackReorderLow:
			res, err := runUnorderedCase(ctx, pairs, seed, repeat, rackReorderLowProfile())
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		case caseRackReorderHigh:
			res, err := runUnorderedCase(ctx, pairs, seed, repeat, rackReorderHighProfile())
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		case caseRackBurstLoss:
			res, err := runUnorderedCase(ctx, pairs, seed, repeat, rackBurstLossProfile())
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
