// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

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
