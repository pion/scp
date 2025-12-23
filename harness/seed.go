// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

const defaultSeed int64 = 1

func resolveSeed(seed int64) int64 {
	if seed != 0 {
		return seed
	}

	return defaultSeed
}
