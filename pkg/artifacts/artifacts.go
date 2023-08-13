package artifacts

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s/docker"
	ms "github.com/mitchellh/mapstructure"
	corev1 "k8s.io/api/core/v1"
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
func FromResource(resource unstructured.Unstructured, cluster k8s.Cluster) (*Artifact, error) {
	nestedKeys := getContainerNestedKeys(resource.GetKind())
	images := make([]string, 0)
	credentials := make([]docker.Auth, 0)
	cTypes := []string{"containers", "ephemeralContainers", "initContainers"}
	podSpec, err := getWorkloadPodSpec(resource)
	if err != nil {
		return nil, err
	}
	var serverAuths map[string]docker.Auth
	if cluster != nil {
		serverAuths, err = cluster.ListImagePullSecretsByPodSpec(context.Background(), podSpec, resource.GetNamespace())
		if err != nil {
			return nil, err
		}
	}
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
			credentials = append(credentials, as)
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

func getWorkloadPodSpec(un unstructured.Unstructured) (*corev1.PodSpec, error) {
	switch un.GetKind() {
	case k8s.KindPod:
		objectMap, ok, err := unstructured.NestedMap(un.Object, []string{"spec"}...)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("unstructured resource do not match Pod spec")
		}
		return mapToPodSpec(objectMap)
	case k8s.KindCronJob:
		objectMap, ok, err := unstructured.NestedMap(un.Object, []string{"spec", "jobTemplate", "spec", "template", "spec"}...)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("unstructured resource do not match Pod spec")
		}
		return mapToPodSpec(objectMap)
	case k8s.KindDeployment:
		objectMap, ok, err := unstructured.NestedMap(un.Object, []string{"spec", "template", "spec"}...)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("unstructured resource do not match Pod spec")
		}
		return mapToPodSpec(objectMap)
	default:
		return nil, nil
	}
}

func mapToPodSpec(objectMap map[string]interface{}) (*corev1.PodSpec, error) {
	ps := &corev1.PodSpec{}
	err := ms.Decode(objectMap, ps)
	if err != nil && len(ps.Containers) == 0 {
		return nil, err
	}
	return ps, nil
}
