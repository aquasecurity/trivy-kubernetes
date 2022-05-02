package artifacts

import (
	"io/ioutil"
	"log"
	"path/filepath"
	"reflect"
	"testing"

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
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			artifact, err := FromResource(test.Resource)
			if err != nil {
				t.Fatal(err)
			}
			compare(t, test.Resource, test.ExpectedArtifact, artifact)
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

func compare(t *testing.T, expectedResource unstructured.Unstructured, expectedArtifact, result *Artifact) {
	if expectedArtifact.Name != result.Name {
		t.Errorf("Expected name %v, but got %v", expectedArtifact.Name, result.Name)
	}

	if expectedArtifact.Kind != result.Kind {
		t.Errorf("Expected kind %v, but got %v", expectedArtifact.Kind, result.Kind)
	}

	if !reflect.DeepEqual(expectedArtifact.Images, result.Images) {
		t.Errorf("Expected images %v, but got %v", expectedArtifact.Images, result.Images)
	}

	if !reflect.DeepEqual(expectedResource.Object, result.RawResource) {
		t.Errorf("Expected resources to be equal but it wasn't: \n%v\n%v", expectedResource.Object, result.RawResource)
	}
}
