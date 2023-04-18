package bom

type Result struct {
	Target   string    `json:"Target"`
	Class    string    `json:"Class,omitempty"`
	Type     string    `json:"Type,omitempty"`
	Packages []Package `json:"Packages,omitempty"`
}

type Package struct {
	ID         string     `json:",omitempty"`
	Name       string     `json:",omitempty"`
	Version    string     `json:",omitempty"`
	Properties []KeyValue `json:",omitempty"`
	DependsOn  []string   `json:",omitempty"`
	Digest     string     `json:",omitempty"`
}

type KeyValue struct {
	Name  string
	Value string
}

type TargetMetadata struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type Component struct {
	Type       string `json:"type,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Repository string `json:"repository,omitempty"`
	Registry   string `json:"registry,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

type NodeInfo struct {
	NodeRole                string `json:"node_role,omitempty"`
	NodeName                string `json:"node_name,omitempty"`
	KubeletVersion          string `json:"kubelet_version,omitempty"`
	ContainerRuntimeVersion string `json:"container_runtime_version,omitempty"`
	OsImage                 string `json:"os_image,omitempty"`
	Hostname                string `json:"host_name,omitempty"`
	KernelVersion           string `json:"kernel_version,omitempty"`
	KubeProxyVersion        string `json:"kube_proxy_version,omitempty"`
	OperatingSystem         string `json:"operating_system,omitempty"`
	Architecture            string `json:"architecture,omitempty"`
}
