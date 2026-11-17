package jobs

import (
	"reflect"
	"testing"

	trivy_checks "github.com/aquasecurity/trivy-checks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
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
		map[string]interface{}{
			"id":        "CMD-0001",
			"title":     "kubelet.conf file permissions",
			"key":       "kubeletConfFilePermissions",
			"nodeType":  "worker",
			"audit":     "stat -c %a $kubelet.kubeconfig",
			"platforms": []interface{}{"k8s"},
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
			name:        "select commands for unknown platform (by default, using `k8s`)",
			platform:    "unknown-ks",
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

func TestPlatformJobOptions(t *testing.T) {
	rke2Volume := corev1.Volume{
		Name: "var-lib-rancher-rke2",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/var/lib/rancher/rke2",
				Type: ptr.To(corev1.HostPathDirectory),
			},
		},
	}
	rke2Mount := corev1.VolumeMount{
		Name:      "var-lib-rancher-rke2",
		MountPath: "/var/lib/rancher/rke2",
		ReadOnly:  true,
	}
	callerVolume := corev1.Volume{
		Name: "var-lib-rancher-rke2",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/rancher/rke2"},
		},
	}
	callerMount := corev1.VolumeMount{
		Name:      "var-lib-rancher-rke2",
		MountPath: "/var/lib/rancher/rke2",
	}

	tests := []struct {
		name        string
		platform    string
		opts        []JobOption
		wantVolumes []corev1.Volume
		wantMounts  []corev1.VolumeMount
	}{
		{
			name:        "rke2",
			platform:    "rke2",
			wantVolumes: []corev1.Volume{rke2Volume},
			wantMounts:  []corev1.VolumeMount{rke2Mount},
		},
		{
			name:     "k8s",
			platform: "k8s",
		},
		{
			name:     "rke2 with caller volume",
			platform: "rke2",
			opts: []JobOption{
				WithPodVolumes([]corev1.Volume{callerVolume}),
				WithContainerVolumeMounts([]corev1.VolumeMount{callerMount}),
			},
			wantVolumes: []corev1.Volume{callerVolume},
			wantMounts:  []corev1.VolumeMount{callerMount},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := append([]JobOption{WithTemplate("node-collector")}, tt.opts...)
			opts = append(opts, platformJobOptions(tt.platform)...)
			job, err := GetJob(opts...)
			require.NoError(t, err)

			spec := job.Spec.Template.Spec
			var gotVolumes []corev1.Volume
			for _, v := range spec.Volumes {
				if v.HostPath != nil && v.HostPath.Path == rke2DataDir {
					gotVolumes = append(gotVolumes, v)
				}
			}
			var gotMounts []corev1.VolumeMount
			for _, m := range spec.Containers[0].VolumeMounts {
				if m.MountPath == rke2DataDir {
					gotMounts = append(gotMounts, m)
				}
			}
			assert.Equal(t, tt.wantVolumes, gotVolumes)
			assert.Equal(t, tt.wantMounts, gotMounts)
		})
	}
}
