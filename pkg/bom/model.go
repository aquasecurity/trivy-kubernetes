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
	NodeRole                string
	NodeName                string
	KubeletVersion          string
	ContainerRuntimeVersion string
	OsImage                 string
	Hostname                string
	KernelVersion           string
	KubeProxyVersion        string
	OperatingSystem         string
	Architecture            string
	Images                  []string
}
