// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"os"

	"github.com/pion/scp/internal/cli"
)

func main() {
	if err := cli.Execute(os.Args[1:]); err != nil {
		cli.PrintError(err)
		os.Exit(1)
	}
}
