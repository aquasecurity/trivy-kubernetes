package k8s

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/aquasecurity/trivy-kubernetes/pkg/bom"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s/docker"
)

type MockClusterDynamicClient struct {
	resource dynamic.NamespaceableResourceInterface
}

func NewMockClusterDynamicClient(resource dynamic.NamespaceableResourceInterface) *MockClusterDynamicClient {
	return &MockClusterDynamicClient{
		resource: resource,
	}
}
func (m MockClusterDynamicClient) Resource(schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return m.resource

}

type MockNamespaceableResourceInterface struct {
	err        error
	namespaces []string
}

func NewMockNamespaceableResourceInterface(namespaces []string, err error) *MockNamespaceableResourceInterface {
	return &MockNamespaceableResourceInterface{
		err:        err,
		namespaces: namespaces,
	}
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

func NewMockCluster(dynamicClient dynamic.Interface) *MockCluster {
	return &MockCluster{
		dynamicClient: dynamicClient,
	}
}

// GetDynamicClient returns dynamic.Interface
func (m *MockCluster) GetDynamicClient() dynamic.Interface {
	return m.dynamicClient
}

// Stub methods to satisfy the Cluster interface
func (m *MockCluster) GetCurrentContext() string   { return "" }
func (m *MockCluster) GetCurrentNamespace() string { return "" }
func (m *MockCluster) GetK8sClientSet() kubernetes.Interface {
	return fake.NewClientset()
}
func (m *MockCluster) GetGVRs(bool, []string) ([]schema.GroupVersionResource, error) { return nil, nil }
func (m *MockCluster) GetGVR(string) (schema.GroupVersionResource, error) {
	return schema.GroupVersionResource{}, nil
}
func (m *MockCluster) CreateClusterBom(ctx context.Context) (*bom.Result, error) { return nil, nil }
func (m *MockCluster) GetClusterVersion() string                                 { return "" }
func (m *MockCluster) AuthByResource(resource unstructured.Unstructured) (map[string]docker.Auth, error) {
	return nil, nil
}
func (m *MockCluster) Platform() Platform {
	return Platform{Name: "k8s", Version: "1.23.0"}
}
