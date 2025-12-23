//go:build harness_integration
// +build harness_integration

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"context"
	"testing"
	"time"

	"github.com/pion/scp/internal/scp"
	"github.com/stretchr/testify/require"
)

func TestMaxBurstDeterministicWithoutSeed(t *testing.T) {
	t.Parallel()

	timeout := 20 * time.Second
	pairs := []pair{{
		Left:  scp.LockEntry{Name: "v1", Commit: "aaaaaaaa"},
		Right: scp.LockEntry{Name: "v2", Commit: "bbbbbbbb"},
	}}

	first, err := runCases(context.Background(), []string{caseMaxBurst}, pairs, 0, 1, timeout, "", interleavingAuto)
	require.NoError(t, err)
	second, err := runCases(context.Background(), []string{caseMaxBurst}, pairs, 0, 1, timeout, "", interleavingAuto)
	require.NoError(t, err)
	require.Len(t, first, len(second))
	for i := range first {
		require.Equal(t, first[i].ForwardBurst, second[i].ForwardBurst)
		require.Equal(t, first[i].ReverseBurst, second[i].ReverseBurst)
		require.Equal(t, first[i].Iteration, second[i].Iteration)
	}
}

func TestMaxBurstRepeat(t *testing.T) {
	t.Parallel()

	timeout := 20 * time.Second
	pairs := []pair{{
		Left:  scp.LockEntry{Name: "v1", Commit: "aaaaaaaa"},
		Right: scp.LockEntry{Name: "v2", Commit: "bbbbbbbb"},
	}}

	results, err := runCases(context.Background(), []string{caseMaxBurst}, pairs, 123, 2, timeout, "", interleavingAuto)
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, 1, results[0].Iteration)
	require.Equal(t, 2, results[1].Iteration)
	require.NotEqual(t, results[0].ForwardBurst, results[1].ForwardBurst)
	require.NotEqual(t, results[0].ReverseBurst, results[1].ReverseBurst)
}

func TestMaxBurstSelfRepeatStable(t *testing.T) {
	t.Parallel()

	timeout := 20 * time.Second
	entry := scp.LockEntry{Name: "v1", Commit: "aaaaaaaa"}
	pairs := []pair{
		{Left: entry, Right: entry},
		{Left: scp.LockEntry{Name: "v2", Commit: "aaaaaaaa"}, Right: scp.LockEntry{Name: "v2", Commit: "aaaaaaaa"}},
	}

	results, err := runCases(context.Background(), []string{caseMaxBurst}, pairs, 123, 2, timeout, "", interleavingAuto)
	require.NoError(t, err)
	require.Len(t, results, 4)

	// self pairs should have symmetric forward/reverse per run
	require.Equal(t, results[0].ForwardBurst, results[0].ReverseBurst)
	require.Equal(t, results[1].ForwardBurst, results[1].ReverseBurst)
	require.Equal(t, results[2].ForwardBurst, results[2].ReverseBurst)
	require.Equal(t, results[3].ForwardBurst, results[3].ReverseBurst)

	// iteration N should be identical across different self pairs
	require.Equal(t, results[0].ForwardBurst, results[2].ForwardBurst)
	require.Equal(t, results[1].ForwardBurst, results[3].ForwardBurst)

	// iterations should differ from each other
	require.NotEqual(t, results[0].ForwardBurst, results[1].ForwardBurst)
}
