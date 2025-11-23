// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"context"
	"testing"

	"github.com/pion/scp/internal/scp"
	"github.com/stretchr/testify/require"
)

func TestRunCasesDefaultsToMaxBurst(t *testing.T) {
	t.Parallel()

	pairs := []pair{{
		Left:  scp.LockEntry{Name: "v1", Commit: "aaaaaaaa"},
		Right: scp.LockEntry{Name: "v2", Commit: "bbbbbbbb"},
	}}

	_, err := runCases(context.Background(), nil, pairs, 123, 1)
	require.ErrorIs(t, err, errNoCases)
}

func TestNormalizeCases(t *testing.T) {
	t.Parallel()

	input := []string{"  max-burst", "max-burst", "other", " ", "other"}
	got := normalizeCases(input)

	require.Equal(t, []string{"max-burst", "other"}, got)
}

func TestRunCasesUnknownCase(t *testing.T) {
	t.Parallel()

	pairs := []pair{{
		Left:  scp.LockEntry{Name: "v1", Commit: "aaaaaaaa"},
		Right: scp.LockEntry{Name: "v2", Commit: "bbbbbbbb"},
	}}

	_, err := runCases(context.Background(), []string{"nope"}, pairs, 123, 1)
	require.ErrorIs(t, err, errUnknownCase)
}
