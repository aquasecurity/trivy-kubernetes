package main

import (
	"github.com/aquasecurity/trivy-kubernetes/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cmd := commands.NewCmd()
	return cmd.Execute()
}
