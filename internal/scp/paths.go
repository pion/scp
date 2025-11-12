// Package scp contains shared helper utilities for the scp CLI tools.
package scp

import "path/filepath"

const (
	DefaultStateDir      = ".scp"
	DefaultManifestFile  = "manifest.json"
	DefaultLockFile      = "lock.json"
	DefaultCacheDirName  = "cache"
	DefaultFeaturesFile  = "features.yaml"
	DefaultOutputDirName = "generated"
)

func DefaultManifestPath() string {
	return filepath.Join(DefaultStateDir, DefaultManifestFile)
}

func DefaultLockPath() string {
	return filepath.Join(DefaultStateDir, DefaultLockFile)
}

func DefaultCacheDir() string {
	return filepath.Join(DefaultStateDir, DefaultCacheDirName)
}

func DefaultOutputDir() string {
	return DefaultOutputDirName
}

func DefaultFeaturesPath() string {
	return DefaultFeaturesFile
}
