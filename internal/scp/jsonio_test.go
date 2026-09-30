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
		{"Empty", "", "", errEmptyStatePath},
	}

	for _, tc := range tests {
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

func TestWriteJSONPreservesDestinationOnEncodeFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	original := []byte(`{"original":true}`)
	require.NoError(t, os.WriteFile(path, original, 0o600))
	require.Error(t, writeJSON(path, make(chan int)))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, data)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestWriteJSONCleansUpAfterRenameFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	require.NoError(t, os.Mkdir(path, 0o750))
	require.Error(t, writeJSON(path, map[string]bool{"valid": true}))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.True(t, entries[0].IsDir())
}

func TestWriteJSONConcurrent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	const writers = 16
	errs := make(chan error, writers)
	for i := range writers {
		go func() {
			errs <- writeJSON(path, map[string]int{"writer": i})
		}()
	}
	for range writers {
		require.NoError(t, <-errs)
	}
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var result map[string]int
	require.NoError(t, json.Unmarshal(data, &result))
	require.Contains(t, result, "writer")
	require.GreaterOrEqual(t, result["writer"], 0)
	require.Less(t, result["writer"], writers)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}
