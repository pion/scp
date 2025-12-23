// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package harness

import (
	"fmt"
	"path/filepath"
)

func packetLogPath(outDir, caseName string, p pair, iteration int) string {
	if outDir == "" {
		return ""
	}

	filename := fmt.Sprintf("%s__%s_iter_%d.jsonl", p.Left.Name, p.Right.Name, iteration)

	return filepath.Join(outDir, "packets", caseName, filename)
}
