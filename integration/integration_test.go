//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-kubernetes/pkg/commands"
	"github.com/aquasecurity/trivy-kubernetes/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
)

// Note: the test required k8s (kind) cluster installed.
// "mage test:k8s" will run this test.

func TestK8s(t *testing.T) {
	t.Run("misconfig and vulnerability scan", func(t *testing.T) {
		// Set up the output file
		outputFile := filepath.Join(t.TempDir(), "output.json")

		osArgs := []string{
			"cluster",
			"--report",
			"summary",
			"-q",
			"--timeout",
			"5m0s",
			"--format",
			"json",
			"--components",
			"workload",
			"--context",
			"kind-kind-test",
			"--output",
			outputFile,
		}

		// Run Trivy
		err := execute(osArgs)
		require.NoError(t, err)

		var got report.ConsolidatedReport
		f, err := os.Open(outputFile)
		require.NoError(t, err)
		defer f.Close()

		err = json.NewDecoder(f).Decode(&got)
		require.NoError(t, err)

		// Flatten findings
		results := lo.FlatMap(got.Findings, func(resource report.Resource, _ int) []types.Result {
			return resource.Results
		})

		// Has vulnerabilities
		assert.True(t, lo.SomeBy(results, func(r types.Result) bool {
			return len(r.Vulnerabilities) > 0
		}))

		// Has misconfigurations
		assert.True(t, lo.SomeBy(results, func(r types.Result) bool {
			return len(r.Misconfigurations) > 0
		}))
	})
	t.Run("kbom cycloneDx", func(t *testing.T) {
		// Set up the output file
		outputFile := filepath.Join(t.TempDir(), "output.json")
		osArgs := []string{
			"cluster",
			"--format",
			"cyclonedx",
			"-q",
			"--context",
			"kind-kind-test",
			"--output",
			outputFile,
		}

		// Run Trivy
		err := execute(osArgs)
		require.NoError(t, err)

		var got *cdx.BOM
		f, err := os.Open(outputFile)
		require.NoError(t, err)
		defer f.Close()

		err = json.NewDecoder(f).Decode(&got)
		require.NoError(t, err)

		assert.Equal(t, got.Metadata.Component.Name, "kind-kind-test")
		assert.Equal(t, got.Metadata.Component.Type, cdx.ComponentType("platform"))

		// Has components
		assert.True(t, len(*got.Components) > 0)

		// Has dependecies
		assert.True(t, lo.SomeBy(*got.Dependencies, func(r cdx.Dependency) bool {
			return len(*r.Dependencies) > 0
		}))

	})
}

func execute(osArgs []string) error {
	// Setup CLI App
	cmd := commands.NewCmd()
	cmd.SetOut(io.Discard)

	// Run Trivy
	cmd.SetArgs(osArgs)
	return cmd.Execute()
}
