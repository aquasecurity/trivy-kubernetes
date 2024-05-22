package k8s

import (
	"fmt"
	"regexp"
	"strings"
)

func getPlatformInfoFromVersion(s string) Platform {
	versionRe := regexp.MustCompile(`v(\d+\.\d+)\.\d+[-+](\w+)(?:[.\-])\w+`)
	subs := versionRe.FindStringSubmatch(s)
	if len(subs) < 3 {
		return Platform{
			Name:    "k8s",
			Version: majorVersion(s),
		}
	}
	return Platform{
		Name:    subs[2],
		Version: subs[1],
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
