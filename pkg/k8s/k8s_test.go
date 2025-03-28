package k8s

import (
	"testing"

	"github.com/aquasecurity/trivy-kubernetes/pkg/bom"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
			fakeKubeconfig, err := fakeConfig.ClientConfig()
			assert.NoError(t, err)
			cluster, err := getCluster(fakeConfig, fakeKubeconfig, nil, "", true)
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

		fakeKubeconfig, err := fakeConfig.ClientConfig()
		assert.NoError(t, err)

		cluster, err := getCluster(fakeConfig, fakeKubeconfig, mapper, "", true)
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

func TestPodInfo(t *testing.T) {
	tests := []struct {
		Name          string
		pod           corev1.Pod
		labelSelector string
		want          *bom.Component
	}{
		{
			Name:          "pod with label",
			labelSelector: "component",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "kube-system",
					Labels:    map[string]string{"component": "kube-apiserver"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Image: "k8s.gcr.io/kube-apiserver:v1.21.1"}},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{{
						Image:   "k8s.gcr.io/kube-apiserver:v1.21.1",
						ImageID: "sha256:18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f",
					},
					},
				},
			},
			want: &bom.Component{
				Namespace: "kube-system",
				Name:      "k8s.io/apiserver",
				Version:   "1.21.1",
				Properties: map[string]string{
					"Name": "pod1",
					"Type": "controlPlane",
				},
				Containers: []bom.Container{
					{
						ID:         "kube-apiserver:v1.21.1",
						Version:    "v1.21.1",
						Repository: "kube-apiserver",
						Registry:   "k8s.gcr.io",
						Digest:     "18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f",
					},
				},
			},
		},
		{
			Name:          "etcd pod with image in another format",
			labelSelector: "component",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "etcd-minikube",
					Namespace: "kube-system",
					Labels:    map[string]string{"component": "etcd"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Image: "registry.k8s.io/etcd:3.5.15-0"}},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{{
						Image:   "registry.k8s.io/etcd:3.5.15-0",
						ImageID: "docker-pullable://registry.k8s.io/etcd@sha256:a6dc63e6e8cfa0307d7851762fa6b629afb18f28d8aa3fab5a6e91b4af60026a",
					},
					},
				},
			},
			want: &bom.Component{
				Namespace: "kube-system",
				Name:      "go.etcd.io/etcd/v3",
				Version:   "3.5.15-0",
				Properties: map[string]string{
					"Name": "etcd-minikube",
					"Type": "controlPlane",
				},
				Containers: []bom.Container{
					{
						ID:         "etcd:3.5.15-0",
						Version:    "3.5.15-0",
						Repository: "etcd",
						Registry:   "registry.k8s.io",
						Digest:     "a6dc63e6e8cfa0307d7851762fa6b629afb18f28d8aa3fab5a6e91b4af60026a",
					},
				},
			},
		},
		{
			Name:          "ingress-nginx controller",
			labelSelector: "app.kubernetes.io/component=controller",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-nginx-controller-8547bfc86c-dr7lq",
					Namespace: "ingress-nginx",
					Labels: map[string]string{
						"app.kubernetes.io/component": "controller",
						"app.kubernetes.io/instance":  "ingress-nginx",
						"app.kubernetes.io/name":      "ingress-nginx",
						"app.kubernetes.io/part-of":   "ingress-nginx",
						"app.kubernetes.io/version":   "1.11.0",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Image: "registry.k8s.io/ingress-nginx/controller:v1.11.0@sha256:a886e56d532d1388c77c8340261149d974370edca1093af4c97a96fb1467cb39"}},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{{
						Image:   "registry.k8s.io/ingress-nginx/controller@sha256:a886e56d532d1388c77c8340261149d974370edca1093af4c97a96fb1467cb39",
						ImageID: "docker-pullable://registry.k8s.io/ingress-nginx/controller@sha256:a886e56d532d1388c77c8340261149d974370edca1093af4c97a96fb1467cb39",
					},
					},
				},
			},
			want: &bom.Component{
				Namespace: "ingress-nginx",
				Name:      "k8s.io/ingress-nginx",
				Version:   "1.11.0",
				Properties: map[string]string{
					"Name": "ingress-nginx-controller-8547bfc86c-dr7lq",
					"Type": "controller",
				},
				Containers: []bom.Container{
					{
						ID:         "ingress-nginx/controller:sha256:a886e56d532d1388c77c8340261149d974370edca1093af4c97a96fb1467cb39",
						Version:    "v1.11.0",
						Repository: "ingress-nginx/controller",
						Registry:   "registry.k8s.io",
						Digest:     "a886e56d532d1388c77c8340261149d974370edca1093af4c97a96fb1467cb39",
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			got, err := PodInfo(test.pod, test.labelSelector)
			assert.NoError(t, err)
			assert.Equal(t, got, test.want)
		})
	}
}

func TestNodeInfo(t *testing.T) {
	tests := []struct {
		Name          string
		node          v1.Node
		labelSelector string
		want          bom.NodeInfo
	}{
		{
			Name: "node info ",
			node: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
					Labels: map[string]string{
						"component":                      "kube-apiserver",
						"node-role.kubernetes.io/master": "",
					},
				},
				Status: v1.NodeStatus{
					NodeInfo: v1.NodeSystemInfo{
						Architecture:            "amd64",
						ContainerRuntimeVersion: "containerd://1.5.2",
						KubeletVersion:          "1.21.1",
						KernelVersion:           "6.5.9-300.fc39.aarch64",
						OperatingSystem:         "linux",
						OSImage:                 "Ubuntu 21.04",
					},
				},
			},

			want: bom.NodeInfo{
				NodeName:                "node1",
				KubeletVersion:          "1.21.1",
				ContainerRuntimeVersion: "containerd://1.5.2",
				OsImage:                 "Ubuntu 21.04",
				Properties: map[string]string{
					"NodeRole":        "master",
					"HostName":        "node1",
					"KernelVersion":   "6.5.9-300.fc39.aarch64",
					"OperatingSystem": "linux",
					"Architecture":    "amd64",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			got := NodeInfo(test.node)
			assert.Equal(t, got, test.want)
		})
	}
}

func TestGetImageId(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		imageId string
	}{
		{
			"sha256 (ex. KinD)",
			"sha256:a6daed8429c54f0008910fc4ecc17aefa1dfcd7cc2ff0089570854d4f95213ed",
			"sha256:a6daed8429c54f0008910fc4ecc17aefa1dfcd7cc2ff0089570854d4f95213ed",
		},
		{
			"docker pullable (ex. Minikube)",
			"docker-pullable://registry.k8s.io/kube-apiserver@sha256:a6daed8429c54f0008910fc4ecc17aefa1dfcd7cc2ff0089570854d4f95213ed",
			"sha256:a6daed8429c54f0008910fc4ecc17aefa1dfcd7cc2ff0089570854d4f95213ed",
		},
		{
			"image name",
			"registry.k8s.io/ingress-nginx/controller:v1.11.0@sha256:a886e56d532d1388c77c8340261149d974370edca1093af4c97a96fb1467cb39",
			"sha256:a886e56d532d1388c77c8340261149d974370edca1093af4c97a96fb1467cb39",
		},
		{
			"id with data",
			"docker.io/library/import-2023-05-12@sha256:346b96f3a1892101fc63ca880036b4f72562961984d208df71c299041c3f0e51",
			"sha256:346b96f3a1892101fc63ca880036b4f72562961984d208df71c299041c3f0e51",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := getImageID(test.input)
			assert.Equal(t, got, test.imageId)
		})
	}

}
