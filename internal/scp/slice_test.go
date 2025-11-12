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
