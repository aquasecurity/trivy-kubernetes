package artifacts

import (
	"os"

	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
)

// Artifact holds information for kubernetes scannable resources
type Artifact struct {
	Namespace string
	Kind      string
	Name      string
	Images    []string
	resource  map[string]interface{}
}

// WriteToFile the resource to a file
func (a *Artifact) WriteToFile(file *os.File) error {
	data, err := yaml.Marshal(a.resource)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	return err
}

// FromResource is a factory method to create an Artifact from an unstructured.Unstructured
func FromResource(resource unstructured.Unstructured) (*Artifact, error) {
	var containersNestedKeys []string

	switch resource.GetKind() {
	case k8s.KindPod:
		containersNestedKeys = []string{"spec", "containers"}
	case k8s.KindCronJob:
		containersNestedKeys = []string{"spec", "jobTemplate", "spec", "template", "spec", "containers"}
	default:
		containersNestedKeys = []string{"spec", "template", "spec", "containers"}
	}

	containers, found, err := unstructured.NestedSlice(resource.Object, containersNestedKeys...)
	if err != nil {
		return nil, err
	}

	images := make([]string, 0)
	if found { // the spec has containers declared
		for _, container := range containers {
			name, found, err := unstructured.NestedString(container.(map[string]interface{}), "image")
			if err != nil {
				return nil, err
			}

			if found {
				images = append(images, name)
			}
		}
	}

	// we don't check found here, if the name is not found it will be an empty string
	name, _, err := unstructured.NestedString(resource.Object, "metadata", "name")
	if err != nil {
		return nil, err
	}

	return &Artifact{
		Namespace: resource.GetNamespace(),
		Kind:      resource.GetKind(),
		Name:      name,
		Images:    images,
		resource:  resource.Object,
	}, nil
}
