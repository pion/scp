// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package scp

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanStatePath(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	abs := filepath.Join(tmpDir, "manifest.json")

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{"Relative", "state/lock.json", filepath.Clean("state/lock.json"), nil},
		{"Absolute", abs, abs, nil},
		{"ParentTraversal", "../lock.json", "", errPathOutsideWorkspace},
		{"Empty", "", ".", nil},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := cleanStatePath(tc.input)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestManifestRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	manifest := &Manifest{
		Schema: 2,
		Repo:   "https://example.com/repo.git",
		Entries: []ManifestEntry{
			{Name: "v1", Selector: "tag:v1.0.0"},
		},
	}

	require.NoError(t, WriteManifest(path, manifest))

	readManifest, err := ReadManifest(path)
	require.NoError(t, err)
	require.Equal(t, manifest, readManifest)
}

func TestLockfileRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "lock.json")

	lock := &Lockfile{
		Schema: 2,
		Entries: []LockEntry{
			{
				Name:       "v1",
				Selector:   "tag:v1.0.0",
				Commit:     "abc123",
				Provenance: "tag",
			},
		},
	}

	require.NoError(t, WriteLock(path, lock))

	got, err := ReadLock(path)
	require.NoError(t, err)
	require.Equal(t, lock, got)
}

func TestCopyJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dst := filepath.Join(dir, "copy.json")

	data := `{"hello":"world"}`
	require.NoError(t, CopyJSON(dst, strings.NewReader(data)))

	contentFile, err := os.Open(dst)
	require.NoError(t, err)
	defer func() {
		_ = contentFile.Close()
	}()

	content, err := io.ReadAll(contentFile)
	require.NoError(t, err)
	require.Equal(t, data, string(content))

	var parsed map[string]string
	require.NoError(t, json.Unmarshal(content, &parsed))
	require.Equal(t, "world", parsed["hello"])
}
