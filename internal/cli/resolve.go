package cli

import (
	"errors"

	"github.com/pion/scp/internal/resolve"
	"github.com/pion/scp/internal/scp"
	"github.com/spf13/cobra"
)

var errNoRefsProvided = errors.New("no refs specified: use --refs or provide positional selectors")

func newResolveCmd() *cobra.Command {
	opts := resolve.Options{}.WithDefaults()
	cmd := &cobra.Command{
		Use:   "resolve",
		Short: "Resolve ref selectors into manifest and lock files",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(opts.Refs) == 0 && len(args) == 0 {
				return errNoRefsProvided
			}

			if len(args) > 0 {
				opts.Refs = append(opts.Refs, args...)
			}

			opts.Refs = scp.SplitAndTrim(opts.Refs)

			ctx := cmd.Context()
			if err := resolve.Run(ctx, opts); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVar(&opts.Refs, "refs", nil, "comma-separated selector list (may repeat)")
	cmd.Flags().StringVar(&opts.Repository, "repo", resolve.DefaultRepository, "repository URL to mirror")
	cmd.Flags().StringVar(&opts.CacheDir, "cache", scp.DefaultCacheDir(), "cache directory for mirrors and checkouts")
	cmd.Flags().BoolVar(
		&opts.IncludePreRelease,
		"include-pre",
		false,
		"include pre-release tags when resolving ranges",
	)
	cmd.Flags().StringVar(
		&opts.ManifestPath,
		"out-manifest",
		scp.DefaultManifestPath(),
		"output path for manifest JSON",
	)
	cmd.Flags().StringVar(
		&opts.LockPath,
		"out-lock",
		scp.DefaultLockPath(),
		"output path for lock JSON",
	)
	cmd.Flags().StringVar(&opts.FreezeAt, "freeze-at", "", "RFC3339 timestamp to pin moving refs")
	cmd.Flags().BoolVar(
		&opts.AllowDirtyLocal,
		"local-allow-dirty",
		false,
		"permit path selectors with local modifications",
	)

	return cmd
}
