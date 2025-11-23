// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"context"
	"time"
)

type networkProfile struct {
	MinDelay    time.Duration
	MaxJitter   time.Duration
	DropPercent float64
	Unordered   bool
	Name        string
}

func lowRTTProfile() networkProfile {
	return networkProfile{
		MinDelay:    10 * time.Millisecond,
		MaxJitter:   10 * time.Millisecond,
		DropPercent: 0.0,
		Unordered:   true,
		Name:        "low-rtt-late",
	}
}

func highRTTProfile() networkProfile {
	return networkProfile{
		MinDelay:    180 * time.Millisecond,
		MaxJitter:   60 * time.Millisecond,
		DropPercent: 0.0,
		Unordered:   true,
		Name:        "high-rtt-late",
	}
}

func dynamicRTTProfile() networkProfile {
	return networkProfile{
		MinDelay:    40 * time.Millisecond,
		MaxJitter:   180 * time.Millisecond,
		DropPercent: 0.0,
		Unordered:   true,
		Name:        "dynamic-rtt-late",
	}
}

func congestionProfile() networkProfile {
	return networkProfile{
		MinDelay:    60 * time.Millisecond,
		MaxJitter:   40 * time.Millisecond,
		DropPercent: 0.02,
		Unordered:   false,
		Name:        "congestion",
	}
}

func lossProfile() networkProfile {
	return networkProfile{
		MinDelay:    40 * time.Millisecond,
		MaxJitter:   20 * time.Millisecond,
		DropPercent: 0.05,
		Unordered:   false,
		Name:        "retransmission",
	}
}

func rackReorderLowProfile() networkProfile {
	return networkProfile{
		MinDelay:    15 * time.Millisecond,
		MaxJitter:   25 * time.Millisecond,
		DropPercent: 1.5, // light loss with reordering
		Unordered:   true,
		Name:        "reorder-low",
	}
}

func rackReorderHighProfile() networkProfile {
	return networkProfile{
		MinDelay:    140 * time.Millisecond,
		MaxJitter:   120 * time.Millisecond,
		DropPercent: 2.5,
		Unordered:   true,
		Name:        "reorder-high",
	}
}

func rackBurstLossProfile() networkProfile {
	return networkProfile{
		MinDelay:    50 * time.Millisecond,
		MaxJitter:   50 * time.Millisecond,
		DropPercent: 4.0,
		Unordered:   true,
		Name:        "burst-loss",
	}
}

func runHandshakeCase(ctx context.Context, pairs []pair, seed int64, repeat int) ([]scenarioResult, error) {
	// handshake is effectively an unordered case with no data; we reuse unordered runner with a tiny payload count.
	return runUnorderedCase(ctx, pairs, seed, repeat, networkProfile{Name: "handshake"})
}

func runUnorderedCase(ctx context.Context, pairs []pair, seed int64, repeat int, profile networkProfile) ([]scenarioResult, error) {
	if len(pairs) == 0 {
		return nil, errInsufficientEntries
	}

	var results []scenarioResult
	for idx, p := range pairs {
		for iter := range repeat {
			seq := idx*repeat + iter
			forward, reverse, metrics, err := runBurstTrafficProfile(ctx, p, seed, seq, profile)
			res := scenarioResult{
				CaseName:     profile.Name,
				Pair:         p,
				Iteration:    iter + 1,
				ForwardBurst: forward,
				ReverseBurst: reverse,
				Metrics:      metrics,
				Passed:       err == nil && forward >= minBurstPackets && reverse >= minBurstPackets,
				Details:      formatMetrics(metrics),
			}
			if err != nil {
				res.Details += " err=" + err.Error()
			}
			results = append(results, res)
		}
	}

	return results, nil
}

func runCongestionCase(ctx context.Context, pairs []pair, seed int64, repeat int) ([]scenarioResult, error) {
	return runUnorderedCase(ctx, pairs, seed, repeat, congestionProfile())
}

func runRetransmissionCase(ctx context.Context, pairs []pair, seed int64, repeat int) ([]scenarioResult, error) {
	return runUnorderedCase(ctx, pairs, seed, repeat, lossProfile())
}
