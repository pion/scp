// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package cli

import (
	"github.com/pion/scp/internal/testcmd"
	"github.com/spf13/cobra"
)

func newTestCmd() *cobra.Command {
	opts := testcmd.DefaultOptions()
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Build runners and execute cross-revision scenarios",
		RunE: func(cmd *cobra.Command, args []string) error {
			return testcmd.Run(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.LockPath, "lock", opts.LockPath, "path to lock.json")
	cmd.Flags().StringVar(
		&opts.PairMode,
		"pairs",
		opts.PairMode,
		"pair selection mode (adjacent|latest-prev|matrix|explicit|self)",
	)
	cmd.Flags().StringSliceVar(
		&opts.IncludeNames,
		"include",
		nil,
		"include only these entries (comma-separated)",
	)
	cmd.Flags().StringSliceVar(
		&opts.ExcludeNames,
		"exclude",
		nil,
		"exclude these entries (comma-separated)",
	)
	cmd.Flags().StringSliceVar(
		&opts.ExplicitPairs,
		"explicit",
		nil,
		"explicit pairs when --pairs=explicit (comma-separated A:B)",
	)
	cmd.Flags().StringSliceVar(
		&opts.Cases,
		"cases",
		nil,
		"scenario IDs to run (comma-separated)",
	)
	cmd.Flags().StringVar(&opts.Timeout, "timeout", opts.Timeout, "overall timeout for each pair")
	cmd.Flags().Int64Var(&opts.Seed, "seed", opts.Seed, "random seed (0=random)")
	cmd.Flags().StringVar(&opts.JUnitPath, "out", opts.JUnitPath, "path to write JUnit XML results")
	cmd.Flags().IntVar(&opts.Repeat, "repeat", opts.Repeat, "number of times to run each pair (>=1)")

	return cmd
}
