package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestGetCurrentNamespace(t *testing.T) {
	tests := []struct {
		Name              string
		Namespace         string
		ExpectedNamespace string
	}{
		{
			Name:              "empty namespace",
			ExpectedNamespace: "default",
		},
		{
			Name:              "non empty namespace",
			Namespace:         "namespace",
			ExpectedNamespace: "namespace",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			fakeConfig := createValidTestConfig(test.Namespace)
			cluster, err := getCluster(fakeConfig, nil, nil)
			assert.NoError(t, err)
			assert.Equal(t, test.ExpectedNamespace, cluster.GetCurrentNamespace())
		})
	}
}

func TestGetGVR(t *testing.T) {
	tests := []struct {
		Resource         string
		GroupVersionKind schema.GroupVersionKind
		ExpectedResource schema.GroupVersionResource
		Err              bool
	}{
		{
			Resource:         "nonexisting",
			GroupVersionKind: schema.GroupVersionKind{Group: "testapi", Version: "test", Kind: "MyObject"},
			Err:              true,
		},
		{
			Resource:         "MyObject",
			GroupVersionKind: schema.GroupVersionKind{Group: "testapi", Version: "test", Kind: "MyObject"},
			ExpectedResource: schema.GroupVersionResource{Resource: "myobjects", Group: "testapi", Version: "test"},
		},
	}

	for _, test := range tests {
		mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{test.GroupVersionKind.GroupVersion()})
		mapper.Add(test.GroupVersionKind, meta.RESTScopeNamespace)

		fakeConfig := createValidTestConfig("")

		cluster, err := getCluster(fakeConfig, mapper, nil)
		assert.NoError(t, err)

		gvr, err := cluster.GetGVR(test.Resource)
		if test.Err {
			assert.Error(t, err)
			continue
		}

		assert.Equal(t, test.ExpectedResource, gvr)
	}
}

func TestIsClusterResource(t *testing.T) {
	for _, r := range getClusterResources() {
		assert.True(t, IsClusterResource(newGVR(r)), r)
	}

	for _, r := range getNamespaceResources() {
		assert.False(t, IsClusterResource(newGVR(r)), r)
	}
}

func newGVR(resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Resource: resource}
}

func createValidTestConfig(namespace string) clientcmd.ClientConfig {
	const (
		server = "https://anything.com:8080"
		token  = "the-token"
	)

	config := clientcmdapi.NewConfig()

	config.CurrentContext = "cluster1"
	config.Clusters["cluster1"] = &clientcmdapi.Cluster{Server: server}
	config.AuthInfos["cluster1"] = &clientcmdapi.AuthInfo{Token: token}
	config.Contexts["cluster1"] = &clientcmdapi.Context{
		Cluster:   "cluster1",
		AuthInfo:  "cluster1",
		Namespace: namespace,
	}

	return clientcmd.NewNonInteractiveClientConfig(*config, "cluster1", &clientcmd.ConfigOverrides{}, nil)
}
