// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"context"
	"testing"

	"github.com/pion/scp/internal/scp"
	"github.com/stretchr/testify/require"
)

func TestMaxBurstDeterministicWithoutSeed(t *testing.T) {
	t.Parallel()

	pairs := []pair{{
		Left:  scp.LockEntry{Name: "v1", Commit: "aaaaaaaa"},
		Right: scp.LockEntry{Name: "v2", Commit: "bbbbbbbb"},
	}}

	first, err := runCases(context.Background(), nil, pairs, 0, 1)
	require.NoError(t, err)
	second, err := runCases(context.Background(), nil, pairs, 0, 1)
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestMaxBurstRepeat(t *testing.T) {
	t.Parallel()

	pairs := []pair{{
		Left:  scp.LockEntry{Name: "v1", Commit: "aaaaaaaa"},
		Right: scp.LockEntry{Name: "v2", Commit: "bbbbbbbb"},
	}}

	results, err := runCases(context.Background(), nil, pairs, 123, 2)
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, 1, results[0].Iteration)
	require.Equal(t, 2, results[1].Iteration)
	require.NotEqual(t, results[0].ForwardBurst, results[1].ForwardBurst)
	require.NotEqual(t, results[0].ReverseBurst, results[1].ReverseBurst)
}
