package artifacts

import (
	"io/ioutil"
	"log"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubectl/pkg/scheme"
)

func TestFromResource(t *testing.T) {
	tests := []struct {
		Name             string
		Resource         unstructured.Unstructured
		ExpectedArtifact *Artifact
	}{
		{"CluterRole", resourceFromFile("clusterrole.yaml"), newArtifact("ClusterRole", "system:monitoring", []string{})},
		{"CluterRoleBinding", resourceFromFile("clusterrolebindings.yaml"), newArtifact("ClusterRoleBinding", "system:coredns", []string{})},
		{"Cronjob", resourceFromFile("cronjob.yaml"), newArtifact("CronJob", "hellocron", []string{"busybox:1.28"})},
		{"DeploymentWithSidecar", resourceFromFile("deploy.yaml"), newArtifact("Deployment", "deploy1", []string{"ubuntu:latest"})},
		{"Deployment", resourceFromFile("deploy-with-sidecar.yaml"), newArtifact("Deployment", "deploy-with-sidecar", []string{"memcached", "nginx"})},
		{"Pod", resourceFromFile("pod.yaml"), newArtifact("Pod", "prometheus", []string{"ubuntu/prometheus"})},
		{"Role", resourceFromFile("role.yaml"), newArtifact("Role", "kube-proxy", []string{})},
		{"Service", resourceFromFile("service.yaml"), newArtifact("Service", "nginx", []string{})},
		{"InitContainer", resourceFromFile("initcontainer.yaml"), newArtifact("Pod", "initapp", []string{"ubuntu:latest", "alpine:latest", "alpine:latest"})},
		{"EphemeralContainer", resourceFromFile("ephemeral.yaml"), newArtifact("Pod", "ephemeral", []string{"k8s.gcr.io/pause:3.1", "busybox:1.28", "ubuntu:latest"})},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			result, err := FromResource(test.Resource)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, test.ExpectedArtifact.Name, result.Name)
			assert.Equal(t, test.ExpectedArtifact.Kind, result.Kind)
			assert.Equal(t, test.ExpectedArtifact.Images, result.Images)
			assert.Equal(t, test.Resource.Object, result.RawResource)

		})
	}
}

func resourceFromFile(fixture string) unstructured.Unstructured {
	fixture = filepath.Join("testdata", "fixtures", fixture)

	content, err := ioutil.ReadFile(fixture)
	if err != nil {
		log.Fatalf("error reading fixture: %v", err)
	}

	decoder := scheme.Codecs.UniversalDeserializer()
	obj, _, err := decoder.Decode([]byte(content), nil, nil)
	if err != nil {
		log.Fatalf("error decoding: %v", err)
	}

	var u unstructured.Unstructured
	u.Object, err = runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		log.Fatalf("error converting to unstructured: %v", err)
	}

	return u
}

func newArtifact(kind, name string, images []string) *Artifact {
	return &Artifact{
		Kind:   kind,
		Name:   name,
		Images: images,
	}
}
