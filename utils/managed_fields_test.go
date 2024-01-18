package utils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestDeleteManagedFields(t *testing.T) {

	// Dummy Kubernetes resource with managedFields
	sampleResource := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"managedFields": []interface{}{
					map[string]interface{}{
						"apiVersion": "v1",
						"fieldsType": "FieldsV1",
						"fieldsV1": map[string]interface{}{
							"f:metadata": map[string]interface{}{
								"f:annotations": map[string]interface{}{
									".": map[string]interface{}{
										"f:kubectl.kubernetes.io/last-applied-configuration": "sample-pod.yaml",
									},
								},
							},
							"f:spec": map[string]interface{}{
								"f:containers": []interface{}{
									map[string]interface{}{
										"f:image": "nginx:1.14",
									},
								},
							},
						},
						"manager":   "kubectl-client-side-apply",
						"operation": "Update",
						"time":      "2021-03-04T15:51:05Z",

						"resourceVersion": "123456",
						"uid":             "123456",
					},
				},
				"name": "sample-pod",
			},
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"image": "nginx:latest",
					},
				},
			},
		},
	}

	t.Run("deletes managedFields in resources", func(t *testing.T) {

		// Check if the "managedFields" field exists before deletion
		_, managedFieldsExists, err := unstructured.NestedSlice(sampleResource.Object, "metadata", "managedFields")
		assert.NoError(t, err)
		assert.True(t, managedFieldsExists)

		// Delete the "managedFields" field
		err = DeleteManagedFields(sampleResource)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		assert.NoError(t, err)

		// Check if the "managedFields" field exists after deletion
		_, managedFieldsExists, err = unstructured.NestedSlice(sampleResource.Object, "metadata", "managedFields")
		assert.NoError(t, err)
		assert.False(t, managedFieldsExists)
	})

	t.Run("does not delete managedFields if it does not exist", func(t *testing.T) {

		// Check if the "managedFields" field exists before deletion
		_, managedFieldsExists, err := unstructured.NestedSlice(sampleResource.Object, "metadata", "managedFields")
		assert.NoError(t, err)
		assert.False(t, managedFieldsExists)

		// Delete the "managedFields" field
		err = DeleteManagedFields(sampleResource)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		assert.NoError(t, err)

		// Check if the "managedFields" field exists after deletion
		_, managedFieldsExists, err = unstructured.NestedSlice(sampleResource.Object, "metadata", "managedFields")
		assert.NoError(t, err)
		assert.False(t, managedFieldsExists)
	})

}
