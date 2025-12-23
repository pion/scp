// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import "time"

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

func mediaHEVCProfile() networkProfile {
	return networkProfile{
		MinDelay:    10 * time.Millisecond,
		MaxJitter:   5 * time.Millisecond,
		DropPercent: 3.0,
		Unordered:   true,
		Name:        "media-hevc",
	}
}
