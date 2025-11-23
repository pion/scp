// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package testcmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pion/scp/internal/scp"
	"github.com/stretchr/testify/require"
)

func TestRunMaxBurstWritesJUnit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lock.json")
	lock := &scp.Lockfile{
		Entries: []scp.LockEntry{
			{Name: "v1", Selector: "tag:v1.0.0", Commit: "aaaaaaaa", Provenance: "tag"},
			{Name: "v2", Selector: "tag:v2.0.0", Commit: "bbbbbbbb", Provenance: "tag"},
		},
	}
	require.NoError(t, scp.WriteLock(lockPath, lock))

	junitPath := filepath.Join(dir, "reports", "junit.xml")
	opts := Options{
		LockPath:  lockPath,
		PairMode:  "matrix",
		Cases:     []string{caseMaxBurst},
		Seed:      42,
		JUnitPath: junitPath,
		Repeat:    1,
	}

	require.NoError(t, Run(context.Background(), opts))
	data, err := os.ReadFile(junitPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "testsuite")
}
