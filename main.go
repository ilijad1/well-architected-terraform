package main

import (
	"os"

	"github.com/ilijad1/well-architected-terraform/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(2)
	}
}
