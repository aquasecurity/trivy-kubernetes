package artifacts

import (
	"errors"
	"os"

	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
)

type Artifact struct {
	Namespace string
	Kind      string
	Name      string
	Images    []string
	resource  map[string]interface{}
}

func (a *Artifact) WriteToFile(file *os.File) error {
	data, err := yaml.Marshal(a.resource)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	return err
}

func FromResource(resource unstructured.Unstructured) (*Artifact, error) {
	var containersNestedKeys []string

	switch resource.GetKind() {
	case k8s.KindPod:
		metadata := resource.GetOwnerReferences()
		if metadata != nil {
			// ignore pod to avoid duplication because it is owned by another resource which will also be scanned
			return nil, nil
		}
		containersNestedKeys = []string{"spec", "containers"}
	case k8s.KindJob:
		metadata := resource.GetOwnerReferences()
		if metadata != nil {
			// ignore pod to avoid duplication because it is owned by another resource which will also be scanned
			return nil, nil
		}
		containersNestedKeys = []string{"spec", "template", "spec", "containers"}
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
			if !found {
				return nil, errors.New("not found")
			}

			images = append(images, name)
		}
	}

	name, found, err := unstructured.NestedString(resource.Object, "metadata", "name")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("not found")
	}

	return &Artifact{
		Namespace: resource.GetNamespace(),
		Kind:      resource.GetKind(),
		Name:      name,
		Images:    images,
		resource:  resource.Object,
	}, nil
}
