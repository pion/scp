// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package scp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitAndTrim(t *testing.T) {
	t.Parallel()

	input := []string{" alpha ,beta", "gamma,,", " delta "}
	got := SplitAndTrim(input)
	want := []string{"alpha", "beta", "gamma", "delta"}

	require.Equal(t, want, got)
}
