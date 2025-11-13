// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package update

import "errors"

var (
	errMissingManifestPath = errors.New("update: manifest path is required")
	errMissingLockPath     = errors.New("update: lock path is required")
	errNotImplemented      = errors.New("update: implementation pending")
)

