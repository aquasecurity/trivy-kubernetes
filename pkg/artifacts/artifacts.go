package artifacts

import (
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s/docker"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Artifact holds information for kubernetes scannable resources
type Artifact struct {
	Namespace   string
	Kind        string
	Labels      map[string]string
	Name        string
	Images      []string
	Credentials []docker.Auth
	RawResource map[string]interface{}
}

// FromResource is a factory method to create an Artifact from an unstructured.Unstructured
func FromResource(resource unstructured.Unstructured, serverAuths map[string]docker.Auth) (*Artifact, error) {
	nestedKeys := getContainerNestedKeys(resource.GetKind())
	images := make([]string, 0)
	credentials := make([]docker.Auth, 0)
	cTypes := []string{"containers", "ephemeralContainers", "initContainers"}

	for _, t := range cTypes {
		cTypeImages, err := extractImages(resource, append(nestedKeys, t))
		if err != nil {
			return nil, err
		}
		images = append(images, cTypeImages...)
		for _, im := range cTypeImages {
			as, err := k8s.MapContainerNamesToDockerAuths(im, serverAuths)
			if err != nil {
				return nil, err
			}
			if as != nil {
				credentials = append(credentials, *as)
			}
		}
	}

	// we don't check found here, if the name is not found it will be an empty string
	name, _, err := unstructured.NestedString(resource.Object, "metadata", "name")
	if err != nil {
		return nil, err
	}
	var labels map[string]string
	if resource.GetKind() == "Node" {
		labels = resource.GetLabels()
	}

	return &Artifact{
		Namespace:   resource.GetNamespace(),
		Kind:        resource.GetKind(),
		Labels:      labels,
		Name:        name,
		Images:      images,
		Credentials: credentials,
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
