package artifacts

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
)

// Artifact holds information for kubernetes scannable resources
type Artifact struct {
	Namespace   string
	Kind        string
	Name        string
	Images      []string
	RawResource map[string]interface{}
}

// FromResource is a factory method to create an Artifact from an unstructured.Unstructured
func FromResource(resource unstructured.Unstructured) (*Artifact, error) {
	nestedKeys := getContainerNestedKeys(resource.GetKind())

	images := make([]string, 0)

	cTypes := []string{"containers", "ephemeralContainers", "initContainers"}
	for _, t := range cTypes {
		cTypeImages, err := extractImages(resource, append(nestedKeys, t))
		if err != nil {
			return nil, err
		}
		images = append(images, cTypeImages...)
	}

	// we don't check found here, if the name is not found it will be an empty string
	name, _, err := unstructured.NestedString(resource.Object, "metadata", "name")
	if err != nil {
		return nil, err
	}

	return &Artifact{
		Namespace:   resource.GetNamespace(),
		Kind:        resource.GetKind(),
		Name:        name,
		Images:      images,
		RawResource: resource.Object,
	}, nil
}

func extractImages(resource unstructured.Unstructured, keys []string) ([]string, error) {
	containers, found, err := unstructured.NestedSlice(resource.Object, keys...)
	if err != nil {
		return []string{}, err
	}

	if !found {
		return []string{}, nil
	}

	images := make([]string, 0)
	for _, container := range containers {
		name, found, err := unstructured.NestedString(container.(map[string]interface{}), "image")
		if err != nil {
			return []string{}, err
		}

		if found {
			images = append(images, name)
		}
	}

	return images, nil
}

func getContainerNestedKeys(kind string) []string {
	switch kind {
	case k8s.KindPod:
		return []string{"spec"}
	case k8s.KindCronJob:
		return []string{"spec", "jobTemplate", "spec", "template", "spec"}
	default:
		return []string{"spec", "template", "spec"}
	}
}
