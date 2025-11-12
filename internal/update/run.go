package update

import "context"

func Run(ctx context.Context, opts Options) error {
	if opts.ManifestPath == "" {
		return errMissingManifestPath
	}
	if opts.LockPath == "" {
		return errMissingLockPath
	}

	return errNotImplemented
}
