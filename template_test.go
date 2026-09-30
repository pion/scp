// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package scp_test

import (
	"testing"

	"github.com/pion/scp/internal/cli"

	"github.com/stretchr/testify/require"
)

func TestRejectUnexpectedArguments(t *testing.T) {
	t.Parallel()

	for _, command := range []string{"generate", "test", "update"} {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			err := cli.Execute([]string{command, "unexpected"})
			require.ErrorContains(t, err, "unknown command")
		})
	}
}

func TestRejectUnimplementedGlobalFlags(t *testing.T) {
	t.Parallel()

	for _, flag := range []string{"--dry-run", "--verbose"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			err := cli.Execute([]string{"generate", flag})
			require.ErrorContains(t, err, "unknown flag")
		})
	}
}
