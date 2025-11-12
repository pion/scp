package cli

import (
	"github.com/pion/scp/internal/generate"
	"github.com/spf13/cobra"
)

func newGenerateCmd() *cobra.Command {
	opts := generate.DefaultOptions()
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate runners, wrappers, and harness code from a lock file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return generate.Run(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.LockPath, "lock", opts.LockPath, "path to lock.json")
	cmd.Flags().StringVar(&opts.FeaturesPath, "features", opts.FeaturesPath, "path to features.yaml")
	cmd.Flags().StringVar(&opts.OutputDir, "out", opts.OutputDir, "output directory for generated code")
	cmd.Flags().StringVar(&opts.APIName, "package", opts.APIName, "name of generated API package")
	cmd.Flags().StringVar(
		&opts.RunnerProtocol,
		"runner-proto",
		opts.RunnerProtocol,
		"runner transport protocol (stdio-json|rpc)",
	)
	cmd.Flags().StringVar(
		&opts.ModuleMode,
		"modmode",
		opts.ModuleMode,
		"module resolve mode (remote|local-cache)",
	)
	cmd.Flags().StringVar(
		&opts.LicensePath,
		"license",
		opts.LicensePath,
		"optional license header file path",
	)
	cmd.Flags().StringSliceVar(
		&opts.OnlyNames,
		"only",
		nil,
		"optional comma-separated list of lock entries to generate",
	)

	return cmd
}
