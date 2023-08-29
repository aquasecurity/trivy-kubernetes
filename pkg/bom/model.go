package bom

type Result struct {
	ID         string      `json:"name"`
	Type       string      `json:"type,omitempty"`
	Components []Component `json:"components,omitempty"`
	NodesInfo  []NodeInfo  `json:"nodesInfo,omitempty"`
}

type Component struct {
	Namespace  string
	Name       string
	Version    string
	Properties map[string]string
	Containers []Container
}

type Container struct {
	ID         string
	Version    string
	Repository string
	Registry   string
	Digest     string
}

type NodeInfo struct {
	NodeName                string
	KubeletVersion          string
	ContainerRuntimeVersion string
	OsImage                 string
	Properties              map[string]string
	KubeProxyVersion        string
	Images                  []string
}
