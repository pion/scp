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

func TestResolveCaseNamesDefaultsToMaxBurst(t *testing.T) {
	t.Parallel()

	require.Equal(t, []string{caseMaxBurst}, resolveCaseNames(nil))
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

	_, err := runCases(context.Background(), []string{"nope"}, pairs, 123, 1, 5*time.Second, "", interleavingAuto)
	require.ErrorIs(t, err, errUnknownCase)
}
