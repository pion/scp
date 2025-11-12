package cli

import (
	"github.com/pion/scp/internal/update"
	"github.com/spf13/cobra"
)

func newUpdateCmd() *cobra.Command {
	opts := update.DefaultOptions()
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update lock files from manifest entries with floating refs",
		RunE: func(cmd *cobra.Command, args []string) error {
			return update.Run(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.ManifestPath, "manifest", opts.ManifestPath, "path to manifest.json")
	cmd.Flags().StringVar(&opts.LockPath, "lock", opts.LockPath, "path to lock.json to update")
	cmd.Flags().StringSliceVar(&opts.OnlyNames, "only", nil, "comma-separated entry names to refresh")
	cmd.Flags().StringVar(&opts.FreezeAt, "freeze-at", "", "RFC3339 timestamp to pin moving refs")

	return cmd
}
