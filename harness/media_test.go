// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBuildMediaPlanHEVC(t *testing.T) {
	t.Parallel()

	spec := mediaSpec{
		BitrateBps:      14_000_000,
		FramesPerSecond: 30,
		Duration:        2 * time.Second,
		MaxPayload:      burstPayloadOctets,
		Pattern:         defaultMediaPattern,
	}
	plan, err := buildMediaPlan(spec)
	require.NoError(t, err)
	require.Equal(t, 3_500_000, plan.TotalBytes)
	require.Equal(t, 2960, plan.TotalPackets)
	require.Equal(t, time.Second/30, plan.FrameInterval)
	require.Len(t, plan.FrameSizes, 60)
}
