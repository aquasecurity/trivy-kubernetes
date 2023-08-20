package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"
)

var (
	GOPATH = os.Getenv("GOPATH")
	GOBIN  = filepath.Join(GOPATH, "bin")

	ENV = map[string]string{
		"CGO_ENABLED": "0",
	}
)

func version() (string, error) {
	if ver, err := sh.Output("git", "describe", "--tags", "--always"); err != nil {
		return "", err
	} else {
		// Strips the v prefix from the tag
		return strings.TrimPrefix(ver, "v"), nil
	}
}

func buildLdflags() (string, error) {
	ver, err := version()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("-s -w -X=github.com/aquasecurity/trivy-kubernetes/pkg/version.ver=%s", ver), nil
}

type Tool mg.Namespace

// GolangciLint installs golangci-lint
func (Tool) GolangciLint() error {
	const version = "v1.52.2"
	if exists(filepath.Join(GOBIN, "golangci-lint")) {
		return nil
	}
	command := fmt.Sprintf("curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b %s %s", GOBIN, version)
	return sh.Run("bash", "-c", command)
}

// Kind installs kind cluster
func (Tool) Kind() error {
	return sh.RunWithV(ENV, "go", "install", "sigs.k8s.io/kind@v0.19.0")
}

type Test mg.Namespace

// Unit runs unit tests
func (t Test) Unit() error {
	return sh.RunWithV(ENV, "go", "test", "-v", "-short", "-coverprofile=coverage.txt", "-covermode=atomic", "./...")
}

// Integration runs integration tests
func (t Test) Integration() error {
	mg.Deps(Tool{}.Kind)

	err := sh.RunWithV(ENV, "kind", "create", "cluster", "--name", "kind-test")
	if err != nil {
		return err
	}
	defer func() {
		_ = sh.RunWithV(ENV, "kind", "delete", "cluster", "--name", "kind-test")
	}()
	err = sh.RunWithV(ENV, "kubectl", "apply", "-f", "./integration/testdata/fixtures/test_nginx.yaml")
	if err != nil {
		return err
	}
	return sh.RunWithV(ENV, "go", "test", "-v", "-tags=integration", "./integration/...")
}

// Lint runs linters
func Lint() error {
	mg.Deps(Tool{}.GolangciLint)
	return sh.RunV("golangci-lint", "run", "--timeout", "5m")
}

// Tidy makes sure go.mod matches the source code in the module
func Tidy() error {
	return sh.RunV("go", "mod", "tidy")
}

// Build builds trivy-kubernetes
func Build() error {
	if updated, err := target.Dir("trivy-kubernetes", "pkg", "cmd"); err != nil {
		return err
	} else if !updated {
		return nil
	}

	ldflags, err := buildLdflags()
	if err != nil {
		return err
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	return sh.RunWith(ENV, "go", "build", "-ldflags", ldflags, filepath.Join(wd, "cmd", "trivy-kubernetes"))
}

func exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
