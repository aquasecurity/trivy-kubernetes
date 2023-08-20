package compliance

import (
	"embed"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	dir = "spec"

	NSA           = types.Compliance("k8s-nsa")
	CIS           = types.Compliance("k8s-cis")
	PSSBaseline   = types.Compliance("k8s-pss-baseline")
	PSSRestricted = types.Compliance("k8s-pss-restricted")
)

var (
	//go:embed spec
	complainceFS embed.FS

	complianceSpecs = make(map[string]spec.ComplianceSpec)
)

// Load compliance specs
func init() {
	dirs, _ := complainceFS.ReadDir(dir)
	for _, r := range dirs {
		if !strings.Contains(r.Name(), ".yaml") {
			continue
		}

		s, err := parseSpec(fmt.Sprintf("%s/%s", dir, r.Name()))
		if err != nil {
			log.Fatal(err)
		}
		complianceSpecs[s.Spec.ID] = s
	}
}

func parseSpec(filePath string) (spec.ComplianceSpec, error) {
	file, err := complainceFS.Open(filePath)
	if err != nil {
		return spec.ComplianceSpec{}, err
	}
	defer file.Close()

	var fileSpec spec.ComplianceSpec
	if err = yaml.NewDecoder(file).Decode(&fileSpec); err != nil {
		return spec.ComplianceSpec{}, err
	}

	return fileSpec, nil
}

// GetSpec accepts compliance flag name/path and return builtin or file system loaded spec
func GetSpec(specName string) (spec.ComplianceSpec, error) {
	return spec.GetComplianceSpec(specName, complianceSpecs)
}
