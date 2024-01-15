package utils

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func DeleteManagedFields(resource *unstructured.Unstructured) error {
	// Check if the "metadata" field exists

	metadata, metadataExists, err := unstructured.NestedMap(resource.Object, "metadata")
	if err != nil {
		return err
	}

	// If the "metadata" field exists, check if the "managedFields" field exists

	if metadataExists {
		_, managedFieldsExists, err := unstructured.NestedSlice(metadata, "managedFields")
		if err != nil {
			return err
		}

		// If the "managedFields" field exists, delete it
		if managedFieldsExists {
			delete(metadata, "managedFields")

			// Update the "metadata" field in the original object
			err = unstructured.SetNestedMap(resource.Object, metadata, "metadata")
			if err != nil {
				return err
			}
		}
	}

	return nil
}
