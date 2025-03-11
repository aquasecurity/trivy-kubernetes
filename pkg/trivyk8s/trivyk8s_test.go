package trivyk8s

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/bom"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type MockClusterDynamicClient struct {
	resource dynamic.NamespaceableResourceInterface
}

func (m MockClusterDynamicClient) Resource(schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return m.resource

}

type MockNamespaceableResourceInterface struct {
	err        error
	namespaces []string
}

func (m MockNamespaceableResourceInterface) Namespace(s string) dynamic.ResourceInterface {
	return nil
}

func (m MockNamespaceableResourceInterface) Create(ctx context.Context, obj *unstructured.Unstructured, options metav1.CreateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return &unstructured.Unstructured{}, nil
}

func (m MockNamespaceableResourceInterface) Update(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return &unstructured.Unstructured{}, nil
}

func (m MockNamespaceableResourceInterface) UpdateStatus(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return &unstructured.Unstructured{}, nil
}

func (m MockNamespaceableResourceInterface) Delete(ctx context.Context, name string, options metav1.DeleteOptions, subresources ...string) error {
	return nil
}

func (m MockNamespaceableResourceInterface) DeleteCollection(ctx context.Context, options metav1.DeleteOptions, listOptions metav1.ListOptions) error {
	return nil
}

func (m MockNamespaceableResourceInterface) Get(ctx context.Context, name string, options metav1.GetOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return &unstructured.Unstructured{}, nil
}

func (m MockNamespaceableResourceInterface) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return nil, nil
}

func (m MockNamespaceableResourceInterface) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, options metav1.PatchOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return &unstructured.Unstructured{}, nil
}

func (m MockNamespaceableResourceInterface) Apply(ctx context.Context, name string, obj *unstructured.Unstructured, options metav1.ApplyOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return &unstructured.Unstructured{}, nil
}

func (m MockNamespaceableResourceInterface) ApplyStatus(ctx context.Context, name string, obj *unstructured.Unstructured, options metav1.ApplyOptions) (*unstructured.Unstructured, error) {
	return &unstructured.Unstructured{}, nil
}

func (m MockNamespaceableResourceInterface) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	if m.err != nil {
		return nil, m.err
	}
	result := &unstructured.UnstructuredList{}
	for _, namespace := range m.namespaces {
		result.Items = append(result.Items, unstructured.Unstructured{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name": namespace,
				},
			},
		})
	}
	return result, nil
}

type MockCluster struct {
	dynamicClient dynamic.Interface
}

func newMockCluster(dynamicClient dynamic.Interface) *MockCluster {
	return &MockCluster{
		dynamicClient: dynamicClient,
	}
}

// GetDynamicClient returns dynamic.Interface
func (m *MockCluster) GetDynamicClient() dynamic.Interface {
	return m.dynamicClient
}

// Stub methods to satisfy the Cluster interface
func (m *MockCluster) GetCurrentContext() string                                     { return "" }
func (m *MockCluster) GetCurrentNamespace() string                                   { return "" }
func (m *MockCluster) GetK8sClientSet() *kubernetes.Clientset                        { return nil }
func (m *MockCluster) GetGVRs(bool, []string) ([]schema.GroupVersionResource, error) { return nil, nil }
func (m *MockCluster) GetGVR(string) (schema.GroupVersionResource, error) {
	return schema.GroupVersionResource{}, nil
}
func (m *MockCluster) CreateClusterBom(ctx context.Context) (*bom.Result, error) { return nil, nil }
func (m *MockCluster) GetClusterVersion() string                                 { return "" }
func (m *MockCluster) AuthByResource(resource unstructured.Unstructured) (map[string]docker.Auth, error) {
	return nil, nil
}
func (m *MockCluster) Platform() k8s.Platform { return k8s.Platform{} }

func TestGetNamespaces(t *testing.T) {
	tests := []struct {
		name               string
		includeNamespaces  []string
		excludeNamespaces  []string
		mockNamespaces     []string
		mockError          error
		expectedNamespaces []string
		expectedError      error
	}{
		{
			name:               "No includeNamespaces, no excludeNamespaces",
			includeNamespaces:  nil,
			excludeNamespaces:  nil,
			mockNamespaces:     nil,
			expectedNamespaces: []string{},
			expectedError:      nil,
		},
		{
			name:               "Include namespaces set",
			includeNamespaces:  []string{"namespace1", "namespace2"},
			excludeNamespaces:  nil,
			mockNamespaces:     nil,
			expectedNamespaces: []string{"namespace1", "namespace2"},
			expectedError:      nil,
		},
		{
			name:               "Exclude namespaces set but no namespaces in cluster",
			includeNamespaces:  nil,
			excludeNamespaces:  []string{"namespace3"},
			mockNamespaces:     nil,
			expectedNamespaces: []string{},
			expectedError:      nil,
		},
		{
			name:               "Exclude namespaces set with namespaces in cluster",
			includeNamespaces:  nil,
			excludeNamespaces:  []string{"namespace3"},
			mockNamespaces:     []string{"namespace1", "namespace2", "namespace3"},
			expectedNamespaces: []string{"namespace1", "namespace2"},
			expectedError:      nil,
		},
		{
			name:               "Error in listing namespaces",
			includeNamespaces:  nil,
			excludeNamespaces:  []string{"namespace3"},
			mockError:          fmt.Errorf("some error"),
			expectedNamespaces: []string{},
			expectedError:      fmt.Errorf("unable to list namespaces: %v", fmt.Errorf("some error")),
		},
		{
			name:              "Forbidden error",
			includeNamespaces: nil,
			excludeNamespaces: []string{"namespace3"},
			mockError: errors.NewForbidden(schema.GroupResource{
				Group:    "",
				Resource: "namespaces",
			}, "namespaces", fmt.Errorf("forbidden")),
			expectedNamespaces: []string{},
			expectedError:      fmt.Errorf("'exclude namespaces' option requires a cluster role with permissions to list namespaces"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &client{
				includeNamespaces: tt.includeNamespaces,
				excludeNamespaces: tt.excludeNamespaces,
				cluster: newMockCluster(MockClusterDynamicClient{
					resource: MockNamespaceableResourceInterface{
						err:        tt.mockError,
						namespaces: tt.mockNamespaces,
					},
				}),
			}

			// Run the test
			namespaces, err := client.getNamespaces()

			// Assert the expected values
			assert.ElementsMatch(t, namespaces, tt.expectedNamespaces)

			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

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

func TestListSpecificArtifacts(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	k3sContainer, err := k3s.Run(ctx, "rancher/k3s:v1.27.1-k3s1")
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, k3sContainer)

	kubeConfigYaml, err := k3sContainer.GetKubeConfig(ctx)
	require.NoError(t, err)

	configPath := path.Join(t.TempDir(), "kubeconfig")
	err = os.WriteFile(configPath, kubeConfigYaml, 0644)
	require.NoError(t, err)

	provider, err := testcontainers.ProviderDocker.GetProvider()
	require.NoError(t, err)

	images := []string{
		"nginx:1.14.1",
		"nginx:1.27.4",
	}

	for _, image := range images {
		err = provider.PullImage(ctx, image)
		require.NoError(t, err)
	}

	tests := []struct {
		name              string
		namespace         string
		resources         []string
		kinds             []string
		action            kubectlAction
		expectedArtifacts []*artifacts.Artifact
	}{
		{
			"good way for pod",
			"default",
			[]string{filepath.Join("testdata", "single-pod.yaml")},
			[]string{"pod"},
			nil,
			[]*artifacts.Artifact{
				{
					Namespace:   "default",
					Kind:        "Pod",
					Labels:      nil,
					Name:        "nginx-pod",
					Images:      []string{"nginx:1.14.1"},
					Credentials: []docker.Auth{},
				},
			},
		},
		{
			"use last-applied-config",
			"default",
			[]string{filepath.Join("testdata", "single-pod.yaml")},
			[]string{"pod"},
			func() error {
				return exec.Command("kubectl", "set", "image", "pod/nginx-pod", "test-nginx=nginx:1.27.4", "--kubeconfig", configPath).Run()
			},
			[]*artifacts.Artifact{
				{
					Namespace:   "default",
					Kind:        "Pod",
					Labels:      nil,
					Name:        "nginx-pod",
					Images:      []string{"nginx:1.14.1"},
					Credentials: []docker.Auth{},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, resource := range test.resources {
				err := exec.Command("kubectl", "apply", "-f", resource, "--kubeconfig", configPath).Run()
				require.NoError(t, err)
				err = exec.Command("kubectl", "wait", "--for=condition=Ready", "pods", "--all", "--kubeconfig", configPath).Run()
				require.NoError(t, err)
			}

			cluster, err := k8s.GetCluster(k8s.WithKubeConfig(configPath))
			require.NoError(t, err)

			c := &client{
				cluster:   cluster,
				namespace: test.namespace,
				resources: test.kinds,
			}

			if test.action != nil {
				require.NoError(t, test.action())
			}

			artifacts, err := c.ListSpecificArtifacts(ctx)
			for i := range test.expectedArtifacts {
				artifacts[i].RawResource = nil
			}

			require.NoError(t, err)
			assert.Equal(t, test.expectedArtifacts, artifacts)
		})
	}
}
