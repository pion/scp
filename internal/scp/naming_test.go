// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package scp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSlugify(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"":              "entry",
		"Hello World!":  "hello_world",
		"  multiple  ":  "multiple",
		"***":           "entry",
		"MiXeD-Case123": "mixed_case123",
	}

	for input, want := range tests {
		got := Slugify(input)
		require.Equal(t, want, got, "Slugify(%q)", input)
	}
}

func TestWithSuffix(t *testing.T) {
	t.Parallel()

	got := WithSuffix("Feature", "ABCDEF123456")
	want := "feature_abcdef1"
	require.Equal(t, want, got)

	got = WithSuffix("already_suffix_abcdef1", "abcdef1234")
	require.Equal(t, "already_suffix_abcdef1", got)
}

func TestNameForSelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		desc   string
		raw    string
		typ    SelectorType
		value  string
		commit string
		want   string
	}{
		{"Tag", "tag:v1.0.0", SelectorTag, "v1.0.0", "abc", "v1_0_0"},
		{"Branch", "branch:main", SelectorBranch, "main", "abcdef1", "branch_main_abcdef1"},
		{"PR", "pr:42", SelectorPR, "42", "ff00ee", "pr_42_ff00ee"},
		{"Commit", "commit:facefeed", SelectorCommit, "facefeed", "facefeed", "sha_facefee"},
		{"Path", "path:/tmp", SelectorPath, "/tmp", "1234567", "local_tmp_1234567"},
		{"Default", "custom:thing", SelectorType("custom"), "thing", "deadbeef", "custom_thing_deadbee"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			got := NameForSelector(tc.raw, tc.typ, tc.value, tc.commit)
			require.Equal(t, tc.want, got, "NameForSelector(%q, %v, %q, %q)",
				tc.raw, tc.typ, tc.value, tc.commit)
		})
	}
}
