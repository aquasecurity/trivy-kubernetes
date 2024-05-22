package model

type SpecVersion struct {
	Name           string
	Version        string `yaml:"cluster_version"`
	Op             string `yaml:"op"`
	CisSpecName    string `yaml:"spec_name"`
	CisSpecVersion string `yaml:"spec_version"`
}

type Mapper struct {
	VersionMapping map[string][]SpecVersion `yaml:"version_mapping"`
}
