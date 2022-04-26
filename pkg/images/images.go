package images

import (
	"context"
	"fmt"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Image ...
type Image struct {
	Resource string
	Name     string
	Image    string
}

type client struct {
	dynamicClient dynamic.Interface
}

func New(dynamicClient dynamic.Interface) *client {
	return &client{dynamicClient}
}

// ListAllByNamespace ...
func (c *client) ListAllByNamespace(ctx context.Context, namespace string) ([]Image, error) {
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	images := make([]Image, 0)

	resources, err := c.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("can't list resource %v - %v", gvr, err)
	}

	for _, resource := range resources.Items {
		images = append(images, parseKubernetesResource(string(gvr.Resource), resource)...)
	}

	return images, nil
}

func parseKubernetesResource(gvr string, resource unstructured.Unstructured) []Image {
	images := make([]Image, 0)

	spec := resource.Object["spec"].(map[string]interface{})
	metadata := resource.Object["metadata"].(map[string]interface{})

	kind := "Pod"
	name := ""
	if metadata["ownerReferences"] != nil {
		ownerReferences := metadata["ownerReferences"].([]interface{})
		references := ownerReferences[0].(map[string]interface{})
		kind = references["kind"].(string)
		name = references["name"].(string)
	}

	for _, container := range spec["containers"].([]interface{}) {
		container := container.(map[string]interface{})
		if name == "" {
			name = container["name"].(string)
		}
		images = append(images, Image{Resource: kind, Name: name, Image: container["image"].(string)})
	}

	return images
}
