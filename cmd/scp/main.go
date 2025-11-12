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
