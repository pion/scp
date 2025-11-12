package scp

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		raw          string
		wantType     SelectorType
		wantValue    string
		wantFloating bool
		wantErr      error
	}{
		{
			name:         "Tag",
			raw:          "tag:v1.2.3",
			wantType:     SelectorTag,
			wantValue:    "v1.2.3",
			wantFloating: false,
		},
		{
			name:         "BranchFloating",
			raw:          "branch:main",
			wantType:     SelectorBranch,
			wantValue:    "main",
			wantFloating: true,
		},
		{
			name:      "Commit",
			raw:       "commit:abc123",
			wantType:  SelectorCommit,
			wantValue: "abc123",
		},
		{
			name:         "PullRequest",
			raw:          "pr:42",
			wantType:     SelectorPR,
			wantValue:    "42",
			wantFloating: true,
		},
		{
			name:      "PathRelative",
			raw:       "path:foo/bar",
			wantType:  SelectorPath,
			wantValue: filepath.Join(".", "foo", "bar"),
		},
		{
			name:         "RangeFloating",
			raw:          "range:>=1.0.0 <1.1.0",
			wantType:     SelectorRange,
			wantValue:    ">=1.0.0 <1.1.0",
			wantFloating: true,
		},
		{
			name:    "Empty",
			raw:     "   ",
			wantErr: errSelectorEmpty,
		},
		{
			name:    "MissingType",
			raw:     "no-prefix",
			wantErr: errSelectorMissingType,
		},
		{
			name:    "Unsupported",
			raw:     "foo:bar",
			wantErr: errSelectorUnsupported,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sel, err := ParseSelector(tc.raw)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantType, sel.Type)
			require.Equal(t, tc.wantValue, sel.Value)
			require.Equal(t, tc.wantFloating, sel.IsFloating)
			require.Equal(t, tc.raw, sel.Raw)
		})
	}
}
