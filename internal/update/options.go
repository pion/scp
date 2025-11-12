package update

import "github.com/pion/scp/internal/scp"

type Options struct {
	ManifestPath string
	LockPath     string
	OnlyNames    []string
	FreezeAt     string
}

func DefaultOptions() Options {
	return Options{
		ManifestPath: scp.DefaultManifestPath(),
		LockPath:     scp.DefaultLockPath(),
	}
}
