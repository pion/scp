// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func Execute(args []string) error {
	root := newRootCmd()
	root.SetArgs(args)
	ctx := context.Background()

	if err := root.ExecuteContext(ctx); err != nil {
		return err
	}

	return nil
}

func PrintError(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scp",
		Short: "scp is a generator for multi-revision Pion SCTP testing",
		Long: `scp resolves references to github.com/pion/sctp, generates deterministic
harnesses, and runs cross-version compatibility tests.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose logging")
	cmd.PersistentFlags().Bool("dry-run", false, "show actions without writing results")

	cmd.AddCommand(newResolveCmd())
	cmd.AddCommand(newUpdateCmd())
	cmd.AddCommand(newGenerateCmd())
	cmd.AddCommand(newTestCmd())

	return cmd
}
