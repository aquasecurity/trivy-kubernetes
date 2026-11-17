package k8s

import (
	"fmt"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/util/version"
)

// getPlatformInfoFromVersion returns the distribution named in the build metadata
// of a server git version, such as "rke2" in "v1.36.6+rke2r1", or "k8s" when
// there is none.
func getPlatformInfoFromVersion(s string) Platform {
	v, err := version.ParseSemantic(s)
	if err != nil {
		return Platform{
			Name:    native,
			Version: majorVersion(s),
		}
	}
	name := native
	for _, distro := range []string{k3s, rke2} {
		if strings.HasPrefix(v.BuildMetadata(), distro) {
			name = distro
			break
		}
	}
	return Platform{
		Name:    name,
		Version: fmt.Sprintf("%d.%d", v.Major(), v.Minor()),
	}
}

func majorVersion(semanticVersion string) string {
	versionRe := regexp.MustCompile(`v(\d+\.\d+)\.\d+`)
	version := semanticVersion
	if !strings.HasPrefix(semanticVersion, "v") {
		version = fmt.Sprintf("v%s", semanticVersion)
	}
	subs := versionRe.FindStringSubmatch(version)
	return subs[1]
}
