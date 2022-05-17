package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

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
