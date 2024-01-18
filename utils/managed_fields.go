package utils

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func DeleteManagedFields(resource *unstructured.Unstructured) error {
	// Check if the "metadata.managedFields" field exists

	_, exists, err := unstructured.NestedSlice(resource.Object, "metadata", "managedFields")
	if err != nil {
		return err
	}

	// If the field exists, then delete it

	if exists {
		metadata, _, err := unstructured.NestedMap(resource.Object, "metadata")
		if err != nil {
			return err
		}

		delete(metadata, "managedFields")

		// Update the "metadata" field in the original object
		err = unstructured.SetNestedMap(resource.Object, metadata, "metadata")
		if err != nil {
			return err
		}
	}

	return nil
}
