package resolve

import "github.com/pion/scp/internal/scp"

const DefaultRepository = "https://github.com/pion/sctp"

type Options struct {
	Refs              []string
	Repository        string
	CacheDir          string
	ManifestPath      string
	LockPath          string
	IncludePreRelease bool
	FreezeAt          string
	AllowDirtyLocal   bool
}

func defaultOptions() Options {
	return Options{
		Repository:        DefaultRepository,
		CacheDir:          scp.DefaultCacheDir(),
		ManifestPath:      scp.DefaultManifestPath(),
		LockPath:          scp.DefaultLockPath(),
		IncludePreRelease: false,
	}
}

func (o Options) WithDefaults() Options {
	def := defaultOptions()
	if o.Repository == "" {
		o.Repository = def.Repository
	}
	if o.CacheDir == "" {
		o.CacheDir = def.CacheDir
	}
	if o.ManifestPath == "" {
		o.ManifestPath = def.ManifestPath
	}
	if o.LockPath == "" {
		o.LockPath = def.LockPath
	}

	return o
}
