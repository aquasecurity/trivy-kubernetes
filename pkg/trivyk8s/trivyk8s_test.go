package trivyk8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestIgnoreNodeByLabel(t *testing.T) {
	tests := []struct {
		name          string
		ignoredLabels map[string]string
		artifact      *artifacts.Artifact
		want          bool
	}{
		{
			name:          "no ignore labels",
			ignoredLabels: map[string]string{},
			artifact:      &artifacts.Artifact{Labels: map[string]string{"a": "b"}},
			want:          false,
		},
		{
			name:          "matching ignore labels",
			ignoredLabels: map[string]string{"a": "b"},
			artifact:      &artifacts.Artifact{Labels: map[string]string{"a": "b"}},
			want:          true,
		},
		{
			name:          "non matching ignore labels",
			ignoredLabels: map[string]string{"a": "b", "c": "d"},
			artifact:      &artifacts.Artifact{Labels: map[string]string{"a": "b"}},
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ignoreNodeByLabel(tt.artifact, tt.ignoredLabels)
			assert.Equal(t, got, tt.want)
		})
	}
}

func TestFilterResource(t *testing.T) {
	tests := []struct {
		name         string
		resourceKind string
		excludeKinds []string
		includeKinds []string
		want         bool
	}{
		{
			name:         "filterKinds with excludeKinds",
			resourceKind: "Pod",
			excludeKinds: []string{"pod"},
			includeKinds: []string{},
			want:         true,
		},
		{
			name:         "filterKinds with includeKinds",
			resourceKind: "Pod",
			includeKinds: []string{"deployment"},
			excludeKinds: []string{},
			want:         true,
		},
		{
			name:         "filterKinds with excludeKinds and includeKinds",
			resourceKind: "Pod",
			includeKinds: []string{"pod"},
			excludeKinds: []string{"pod"},
			want:         false,
		},
		{
			name:         "filterKinds with no excludeKinds and no includeKinds",
			resourceKind: "Pod",
			includeKinds: []string{},
			excludeKinds: []string{},
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterResources(tt.includeKinds, tt.excludeKinds, tt.resourceKind)
			assert.Equal(t, got, tt.want)
		})
	}
}

func TestInitResources(t *testing.T) {
	tests := []struct {
		name         string
		includeKinds []string
		excludeKinds []string
		want         []string
	}{
		{
			name:         "scan only pods",
			includeKinds: []string{"pods"},
			excludeKinds: nil,
			want:         []string{k8s.Pods},
		},
		{
			name:         "skip ClusterRoles, Deployments and Ingresses",
			includeKinds: nil,
			excludeKinds: []string{"deployments", "ingresses", "clusterroles"},
			want: []string{
				k8s.ClusterRoleBindings,
				k8s.Nodes,
				k8s.Pods,
				k8s.ReplicaSets,
				k8s.ReplicationControllers,
				k8s.StatefulSets,
				k8s.DaemonSets,
				k8s.CronJobs,
				k8s.Jobs,
				k8s.Services,
				k8s.ServiceAccounts,
				k8s.ConfigMaps,
				k8s.Roles,
				k8s.RoleBindings,
				k8s.NetworkPolicies,
				k8s.ResourceQuotas,
				k8s.LimitRanges,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &client{excludeKinds: tt.excludeKinds, includeKinds: tt.includeKinds}
			c.initResourceList()
			assert.Equal(t, tt.want, c.resources)
		})
	}
}

type kubectlAction func() error

func TestListArtifacts(t *testing.T) {
	const nodeHashName = "node-af4de95017af"

	t.Log("Preparing test environment...")
	t.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	k3sContainer, err := k3s.Run(ctx, "rancher/k3s:v1.27.1-k3s1")
	require.NoError(t, err)

	testcontainers.CleanupContainer(t, k3sContainer)

	kubeConfigYaml, err := k3sContainer.GetKubeConfig(ctx)
	require.NoError(t, err)

	kubeConfigPath := path.Join(t.TempDir(), "kubeconfig")
	err = os.WriteFile(kubeConfigPath, kubeConfigYaml, 0644)
	require.NoError(t, err)

	provider, err := testcontainers.ProviderDocker.GetProvider()
	require.NoError(t, err)

	images := []string{
		"alpine:3.14.1",
		"alpine:3.21.1",
	}
	for _, image := range images {
		err = provider.PullImage(ctx, image)
		require.NoError(t, err)
	}

	customNamespaces := []string{"custom-namespace"}
	defaultNamespaces := []string{"default", "kube-system", "kube-public", "kube-node-lease"}
	for _, ns := range customNamespaces {
		err := exec.Command("kubectl", "create", "namespace", ns, "--kubeconfig", kubeConfigPath).Run()
		require.NoError(t, err)
	}
	// Wait for nodes are running
	err = exec.Command("kubectl", "wait", "--for=condition=Ready", "nodes", "--timeout", "300s", "--all", "--kubeconfig", kubeConfigPath).Run()
	require.NoError(t, err)

	allDefaultPods := kubectlGetArtifacts("pods", kubeConfigPath)

	// Create custom resources
	resources := []string{
		filepath.Join("testdata", "single-pod.yaml"),
		filepath.Join("testdata", "pod-ns1.yaml"),
	}
	for _, resource := range resources {
		err := exec.Command("kubectl", "apply", "-f", resource, "--kubeconfig", kubeConfigPath).Run()
		require.NoError(t, err)
	}
	err = exec.Command("kubectl", "wait", "--for=condition=Ready", "pods", "--timeout", "300s", "--all", "--kubeconfig", kubeConfigPath).Run()
	require.NoError(t, err)

	tests := []struct {
		name              string
		kubeConfigPath    string
		opts              []K8sOption
		action            kubectlAction
		expectedArtifacts []*artifacts.Artifact
	}{
		{
			name:           "good way for pod",
			kubeConfigPath: kubeConfigPath,
			opts: []K8sOption{
				WithIncludeNamespaces([]string{"default"}),
				WithIncludeKinds([]string{"Pod"}),
			},
			action: nil,
			expectedArtifacts: []*artifacts.Artifact{
				{
					Namespace:   "default",
					Kind:        "Pod",
					Labels:      nil,
					Name:        "alpine-runner",
					Images:      []string{"alpine:3.14.1"},
					Credentials: []docker.Auth{},
				},
			},
		},
		{
			name:           "use last-applied-config",
			kubeConfigPath: kubeConfigPath,
			opts: []K8sOption{
				WithIncludeNamespaces([]string{"default"}),
				WithIncludeKinds([]string{"Pod"}),
			},
			action: func() error {
				return exec.Command("kubectl", "set", "image", "pod/alpine-runner", "runner=alpine:3.21.1", "--kubeconfig", kubeConfigPath).Run()
			},
			expectedArtifacts: []*artifacts.Artifact{
				{
					Namespace:   "default",
					Kind:        "Pod",
					Labels:      nil,
					Name:        "alpine-runner",
					Images:      []string{"alpine:3.21.1"},
					Credentials: []docker.Auth{},
				},
			},
		},
		{
			name:           "include only custom-namespace",
			kubeConfigPath: kubeConfigPath,
			opts: []K8sOption{
				WithIncludeNamespaces([]string{"custom-namespace"}),
				WithIncludeKinds([]string{"Pod"}),
			},
			expectedArtifacts: []*artifacts.Artifact{
				{
					Namespace:   "custom-namespace",
					Kind:        "Pod",
					Labels:      nil,
					Name:        "alpine-runner-custom-ns",
					Images:      []string{"alpine:3.14.1"},
					Credentials: []docker.Auth{},
				},
			},
		},
		{
			name:           "exclude default namespaces" + fmt.Sprintf(" (%v)", defaultNamespaces),
			kubeConfigPath: kubeConfigPath,
			opts: []K8sOption{
				WithIncludeKinds([]string{"Pod"}),
				WithExcludeNamespaces(defaultNamespaces),
			},
			expectedArtifacts: []*artifacts.Artifact{
				{
					Namespace:   "custom-namespace",
					Kind:        "Pod",
					Labels:      nil,
					Name:        "alpine-runner-custom-ns",
					Images:      []string{"alpine:3.14.1"},
					Credentials: []docker.Auth{},
				},
			},
		},
		{
			name:           "include unknown namespace",
			kubeConfigPath: kubeConfigPath,
			opts: []K8sOption{
				WithIncludeNamespaces([]string{"custom-namespace-2"}),
				WithIncludeKinds([]string{"Pod"}),
			},
			expectedArtifacts: []*artifacts.Artifact{},
		},
		{
			name:           "No includeNamespaces, no excludeNamespaces - get all pods",
			kubeConfigPath: kubeConfigPath,
			opts: []K8sOption{
				WithIncludeKinds([]string{"Pod"}),
			},
			expectedArtifacts: append(allDefaultPods, &artifacts.Artifact{
				Namespace:   "default",
				Kind:        "Pod",
				Labels:      nil,
				Name:        "alpine-runner",
				Images:      []string{"alpine:3.21.1"},
				Credentials: []docker.Auth{},
			}, &artifacts.Artifact{
				Namespace:   "custom-namespace",
				Kind:        "Pod",
				Labels:      nil,
				Name:        "alpine-runner-custom-ns",
				Images:      []string{"alpine:3.14.1"},
				Credentials: []docker.Auth{},
			}, &artifacts.Artifact{
				Kind: "NodeComponents",
				Name: nodeHashName,
			}, &artifacts.Artifact{
				Kind: "Cluster",
				Name: "k8s.io/kubernetes",
			}, &artifacts.Artifact{
				Namespace: "kube-system",
				Kind:      "ControlPlaneComponents",
				Name:      "kube-dns",
			}, &artifacts.Artifact{
				Namespace: "kube-system",
				Kind:      "ControlPlaneComponents",
				Name:      "metrics-server",
			}),
		},
		{
			name:           "Exclude unknown namespace",
			kubeConfigPath: kubeConfigPath,
			opts: []K8sOption{
				WithExcludeNamespaces([]string{"uncreated-custom-namespace"}),
				WithIncludeKinds([]string{"Pod"}),
			},
			expectedArtifacts: append(allDefaultPods, &artifacts.Artifact{
				Namespace:   "default",
				Kind:        "Pod",
				Labels:      nil,
				Name:        "alpine-runner",
				Images:      []string{"alpine:3.21.1"},
				Credentials: []docker.Auth{},
			}, &artifacts.Artifact{
				Namespace:   "custom-namespace",
				Kind:        "Pod",
				Labels:      nil,
				Name:        "alpine-runner-custom-ns",
				Images:      []string{"alpine:3.14.1"},
				Credentials: []docker.Auth{},
			}),
		},
		// ToDo - add a kube config for limited users
		// 	{
		//			name:               "Forbidden error",
		//			expectedError:      fmt.Errorf("'exclude namespaces' option requires a cluster role with permissions to list namespaces"),
		//	},
	}

	t.Log("Running tests")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cluster, err := k8s.GetCluster(k8s.WithKubeConfig(test.kubeConfigPath))
			require.NoError(t, err)

			c := &client{
				cluster: cluster,
			}
			for _, opt := range test.opts {
				opt(c)
			}

			if test.action != nil {
				require.NoError(t, test.action())
			}

			gotArtifacts, err := c.ListArtifacts(ctx)
			for i := range test.expectedArtifacts {
				if gotArtifacts[i].Kind == "NodeComponents" {
					gotArtifacts[i].Name = nodeHashName
				}
				gotArtifacts[i].RawResource = nil
			}

			require.NoError(t, err)

			sort.Slice(gotArtifacts, func(i, j int) bool {
				return gotArtifacts[i].Name < gotArtifacts[j].Name
			})
			sort.Slice(test.expectedArtifacts, func(i, j int) bool {
				return test.expectedArtifacts[i].Name < test.expectedArtifacts[j].Name
			})
			assert.Equal(t, test.expectedArtifacts, gotArtifacts)
		})
	}
}

func kubectlGetArtifacts(kind, kubeConfigPath string) []*artifacts.Artifact {
	cmd := exec.Command("kubectl", "get", kind, "-A", "-o", "json", "--kubeconfig", kubeConfigPath)
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("can't get all artifacts %q: %v", kind, err)
	}

	var resource unstructured.UnstructuredList
	err = json.Unmarshal(output, &resource)
	if err != nil {
		log.Fatalf("can't parse resources %q: %v", kind, err)
	}

	var artifactsList []*artifacts.Artifact
	for _, res := range resource.Items {

		artifact, err := artifacts.FromResource(res, nil)
		if err != nil {
			log.Fatalf("can't parse resources (%v) to artifact: %v", res, err)
		}
		artifact.RawResource = nil
		artifactsList = append(artifactsList, artifact)
	}

	return artifactsList
}
