// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"testing"

	"github.com/pion/scp/internal/scp"
	"github.com/stretchr/testify/require"
)

func TestSelectEntries(t *testing.T) {
	t.Parallel()

	entries := []scp.LockEntry{
		{Name: "v1", Commit: "a"},
		{Name: "v2", Commit: "b"},
		{Name: "v3", Commit: "c"},
	}

	t.Run("Include", func(t *testing.T) {
		selected, err := selectEntries(entries, nameSet("v1", "v3"), nil)
		require.NoError(t, err)
		require.Len(t, selected, 2)
		require.Equal(t, "v1", selected[0].Name)
		require.Equal(t, "v3", selected[1].Name)
	})

	t.Run("MissingInclude", func(t *testing.T) {
		_, err := selectEntries(entries, nameSet("v4"), nil)
		require.ErrorIs(t, err, errRequestedEntryMissing)
	})

	t.Run("Exclude", func(t *testing.T) {
		selected, err := selectEntries(entries, nil, nameSet("v2"))
		require.NoError(t, err)
		require.Len(t, selected, 2)
		require.Equal(t, []string{"v1", "v3"}, []string{selected[0].Name, selected[1].Name})
	})
}

func TestBuildPairs(t *testing.T) {
	t.Parallel()

	entries := []scp.LockEntry{
		{Name: "v1", Commit: "a"},
		{Name: "v2", Commit: "b"},
		{Name: "v3", Commit: "c"},
	}

	t.Run("Adjacent", func(t *testing.T) {
		pairs, err := buildPairs(entries, "adjacent", nil)
		require.NoError(t, err)
		require.Len(t, pairs, 2)
		require.Equal(t, "v1", pairs[0].Left.Name)
		require.Equal(t, "v2", pairs[0].Right.Name)
	})

	t.Run("LatestPrev", func(t *testing.T) {
		pairs, err := buildPairs(entries, "latest-prev", nil)
		require.NoError(t, err)
		require.Len(t, pairs, 1)
		require.Equal(t, "v2", pairs[0].Left.Name)
		require.Equal(t, "v3", pairs[0].Right.Name)
	})

	t.Run("Matrix", func(t *testing.T) {
		pairs, err := buildPairs(entries, "matrix", nil)
		require.NoError(t, err)
		require.Len(t, pairs, 3)
	})

	t.Run("Explicit", func(t *testing.T) {
		pairs, err := buildPairs(entries, "explicit", []string{"v1:v3", "v2:v3"})
		require.NoError(t, err)
		require.Len(t, pairs, 2)
		require.Equal(t, "v1", pairs[0].Left.Name)
		require.Equal(t, "v3", pairs[0].Right.Name)
	})

	t.Run("Self", func(t *testing.T) {
		pairs, err := buildPairs(entries[:1], "self", nil)
		require.NoError(t, err)
		require.Len(t, pairs, 1)
		require.Equal(t, pairs[0].Left.Name, pairs[0].Right.Name)
	})
}

func nameSet(names ...string) map[string]struct{} {
	if len(names) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}

	return set
}
