// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package resolve

import (
	"context"

	"github.com/pion/scp/internal/scp"
)

func Run(ctx context.Context, opts Options) error {
	opts = opts.WithDefaults()
	if len(opts.Refs) == 0 {
		return errNoRefs
	}

	refs := scp.SplitAndTrim(opts.Refs)
	if len(refs) == 0 {
		return errNoRefsAfterParsing
	}

	mirror, err := scp.EnsureMirror(ctx, opts.Repository, opts.CacheDir)
	if err != nil {
		return err
	}

	resolver := newResolver(opts, mirror)
	resolved, err := resolver.ResolveAll(ctx, refs)
	if err != nil {
		return err
	}

	manifest := &scp.Manifest{
		Schema:  2,
		Repo:    opts.Repository,
		Entries: make([]scp.ManifestEntry, 0, len(resolved)),
	}

	lock := &scp.Lockfile{
		Schema: 2,
		Metadata: scp.LockMetadata{
			Repository: opts.Repository,
		},
		Entries: make([]scp.LockEntry, 0, len(resolved)),
	}

	for _, entry := range resolved {
		manifest.Entries = append(manifest.Entries, scp.ManifestEntry{
			Name:     entry.Name,
			Selector: entry.Selector.Raw,
		})
		lock.Entries = append(lock.Entries, scp.LockEntry{
			Name:       entry.Name,
			Selector:   entry.Selector.Raw,
			Commit:     entry.Commit,
			Provenance: entry.Provenance,
			Labels:     entry.Labels,
		})
	}

	if err := scp.WriteManifest(opts.ManifestPath, manifest); err != nil {
		return err
	}
	if err := scp.WriteLock(opts.LockPath, lock); err != nil {
		return err
	}

	return nil
}

type resolvedEntry struct {
	Name       string
	Selector   scp.Selector
	Commit     string
	Provenance string
	Labels     map[string]string
}
