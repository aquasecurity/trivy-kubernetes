package jobs

import (
	"reflect"
	"testing"

	trivy_checks "github.com/aquasecurity/trivy-checks"
	"github.com/stretchr/testify/assert"
)

func TestLoadCheckFilesByID(t *testing.T) {
	tests := []struct {
		name         string
		commandPaths []string
		wantCmd      map[string][]any
		wantCfg      map[string][]byte
	}{
		{name: "node-collector template", commandPaths: []string{"./testdata/fixture"},
			wantCmd: map[string][]any{
				"CMD-0001": {
					map[string]interface{}{
						"id":        "CMD-0001",
						"title":     "kubelet.conf file permissions",
						"key":       "kubeletConfFilePermissions",
						"nodeType":  "worker",
						"audit":     "stat -c %a $kubelet.kubeconfig",
						"platforms": []interface{}{"k8s", "aks"},
					},
				},
				"CMD-0002": {
					map[string]interface{}{
						"id":        "CMD-0002",
						"title":     "kubelet.conf file permissions",
						"key":       "kubeletConfFilePermissions",
						"nodeType":  "worker",
						"audit":     "stat -c %a $kubelet.kubeconfig",
						"platforms": []interface{}{"k8s", "aks"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCmd, gotCfg := loadCommands(tt.commandPaths, AddChecksByCheckId)
			assert.True(t, reflect.DeepEqual(gotCmd["CMD-0001"], tt.wantCmd["CMD-0001"]))
			assert.True(t, reflect.DeepEqual(gotCmd["CMD-0002"], tt.wantCmd["CMD-0002"]))
			_, ok := gotCfg["kubelet_mapping_cfg.yaml"]
			assert.True(t, ok)
			_, ok = gotCfg["node_cfg.yaml"]
			assert.True(t, ok)
			_, ok = gotCfg["platform_mapping_cfg.yaml"]
			assert.True(t, ok)
		})
	}
}

func TestLoadEmbeddedCommandsByID(t *testing.T) {
	tests := []struct {
		name    string
		wantCmd map[string][]any
		wantCfg map[string][]byte
	}{
		{name: "node-collector template",
			wantCmd: map[string][]any{
				"CMD-0001": {
					map[string]interface{}{
						"id":        "CMD-0001",
						"title":     "API server pod specification file permissions",
						"key":       "kubeAPIServerSpecFilePermission",
						"nodeType":  "master",
						"audit":     "stat -c %a $apiserver.confs",
						"platforms": []interface{}{"k8s", "rke2"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCmd, gotCfg := getEmbeddedCommands(trivy_checks.EmbeddedK8sCommandsFileSystem, trivy_checks.EmbeddedConfigCommandsFileSystem, AddChecksByCheckId)
			assert.True(t, reflect.DeepEqual(gotCmd["CMD-0001"], tt.wantCmd["CMD-0001"]))
			_, ok := gotCfg["kubelet_mapping.yaml"]
			assert.True(t, ok)
			_, ok = gotCfg["node.yaml"]
			assert.True(t, ok)
		})
	}
}

func TestLoadConfigFilesByPlatform(t *testing.T) {
	tests := []struct {
		name         string
		commandPaths []string
		wantCmd      map[string]any
		wantCfg      map[string][]byte
	}{
		{name: "node-collector template", commandPaths: []string{"./testdata/fixture"}, wantCmd: map[string]any{
			"CMD-0001": map[string]interface{}{
				"id":        "CMD-0001",
				"title":     "kubelet.conf file permissions",
				"key":       "kubeletConfFilePermissions",
				"nodeType":  "worker",
				"audit":     "stat -c %a $kubelet.kubeconfig",
				"platforms": []interface{}{"k8s", "aks"},
			},
			"CMD-0002": map[string]interface{}{
				"id":        "CMD-0002",
				"title":     "kubelet.conf file permissions",
				"key":       "kubeletConfFilePermissions",
				"nodeType":  "worker",
				"audit":     "stat -c %a $kubelet.kubeconfig",
				"platforms": []interface{}{"k8s", "aks"},
			},
		},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCmd, gotCfg := loadCommands(tt.commandPaths, AddChecksByPlatform)
			assert.True(t, len(gotCmd["k8s"]) == 2)
			assert.True(t, len(gotCmd["aks"]) == 2)
			_, ok := gotCfg["kubelet_mapping_cfg.yaml"]
			assert.True(t, ok)
			_, ok = gotCfg["node_cfg.yaml"]
			assert.True(t, ok)
			_, ok = gotCfg["platform_mapping_cfg.yaml"]
			assert.True(t, ok)

		})
	}
}

func TestFilterCommands(t *testing.T) {
	tests := []struct {
		name           string
		filterCommands []string
		commandsMap    map[string][]any
		want           NodeCommands
	}{
		{name: "node-collector template",
			filterCommands: []string{"CMD-0001"},
			commandsMap: map[string][]any{
				"CMD-0001": {
					map[string]interface{}{
						"id":        "CMD-0001",
						"title":     "kubelet.conf file permissions",
						"key":       "kubeletConfFilePermissions",
						"nodeType":  "worker",
						"audit":     "stat -c %a $kubelet.kubeconfig",
						"platforms": []interface{}{"k8s", "aks"},
					},
				},
			},
			want: NodeCommands{
				Commands: []any{
					map[string]interface{}{
						"id":        "CMD-0001",
						"title":     "kubelet.conf file permissions",
						"key":       "kubeletConfFilePermissions",
						"nodeType":  "worker",
						"audit":     "stat -c %a $kubelet.kubeconfig",
						"platforms": []interface{}{"k8s", "aks"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterCommandBySpecId(tt.commandsMap, tt.filterCommands)
			assert.True(t, reflect.DeepEqual(got, tt.want))
		})
	}
}

func TestFilterCommandsByPlatform(t *testing.T) {
	commandsK8s := []any{
		map[string]interface{}{
			"id":        "CMD-0001",
			"title":     "kubelet.conf file permissions",
			"key":       "kubeletConfFilePermissions",
			"nodeType":  "worker",
			"audit":     "stat -c %a $kubelet.kubeconfig",
			"platforms": []interface{}{"k8s", "rke2"},
		},
		map[string]interface{}{
			"id":        "CMD-0002",
			"title":     "kubelet.conf file permissions",
			"key":       "kubeletConfFilePermissions",
			"nodeType":  "worker",
			"audit":     "stat -c %a $kubelet.kubeconfig",
			"platforms": []interface{}{"k8s", "rke2"},
		},
	}
	commandsRKE2 := []any{
		map[string]interface{}{
			"id":        "CMD-0001",
			"title":     "kubelet.conf file permissions",
			"key":       "kubeletConfFilePermissions",
			"nodeType":  "worker",
			"audit":     "stat -c %a $kubelet.kubeconfig",
			"platforms": []interface{}{"k8s", "rke2"},
		},
		map[string]interface{}{
			"id":        "CMD-0002",
			"title":     "kubelet.conf file permissions",
			"key":       "kubeletConfFilePermissions",
			"nodeType":  "worker",
			"audit":     "stat -c %a $kubelet.kubeconfig",
			"platforms": []interface{}{"k8s", "rke2"},
		},
	}
	commandsMap := map[string][]any{
		"k8s":  commandsK8s,
		"rke2": commandsRKE2,
	}

	tests := []struct {
		name        string
		platform    string
		commandsMap map[string][]any
		want        *NodeCommands
	}{
		{
			name:        "select k8s commands",
			platform:    "k8s",
			commandsMap: commandsMap,
			want: &NodeCommands{
				Commands: commandsK8s,
			},
		},
		{
			name:        "select RKE2 commands",
			platform:    "rke2",
			commandsMap: commandsMap,
			want: &NodeCommands{
				Commands: commandsRKE2,
			},
		},
		{
			name:        "select AKS commands",
			platform:    "aks",
			commandsMap: commandsMap,
			want: &NodeCommands{
				Commands: commandsK8s,
			},
		},
		{
			name:     "without command maps",
			platform: "aks",
			want: &NodeCommands{
				Commands: make([]any, 0),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterCommandByPlatform(tt.commandsMap, tt.platform)
			assert.True(t, reflect.DeepEqual(got.Commands, tt.want.Commands))
		})
	}
}
