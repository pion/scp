// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package generate

import "errors"

var (
	errMissingLockPath  = errors.New("generate: lock path is required")
	errMissingOutputDir = errors.New("generate: output directory is required")
	errMissingAPIName   = errors.New("generate: package name is required")
)
