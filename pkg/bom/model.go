package bom

type Result struct {
	ID         string      `json:"name"`
	Type       string      `json:"type,omitempty"`
	Version    string      `json:"version,omitempty"`
	Components []Component `json:"components,omitempty"`
	NodesInfo  []NodeInfo  `json:"nodesInfo,omitempty"`
	Properties map[string]string
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

type ClusterInfo struct {
	Name       string `json:"name"`
	Type       string `json:"type,omitempty"`
	Version    string `json:"version,omitempty"`
	Properties map[string]string
}
