// Command vibekiller is a self-hosted security scanner for applications you
// own.
//
// It analyzes a local repository and, optionally, a running instance of that
// same application on a host you have declared, and reports the weaknesses
// that AI-generated code repeatedly ships. Findings are written to the local
// runs/ directory and nowhere else.
//
// This lives under cmd/vibekiller rather than at the module root because
// `go install` names the installed binary after the last element of the
// package path. At the root that element is the module's own last element --
// "Vibe-Killer" -- so everyone who installed it would get a Vibe-Killer
// binary, while every example in the README invokes `vibekiller`. The
// directory name here is what fixes that, so renaming it renames the command.
package main

import (
	"os"

	"github.com/rohitanakiya/Vibe-Killer/internal/cli"
)

func main() {
	os.Exit(cli.Main())
}
