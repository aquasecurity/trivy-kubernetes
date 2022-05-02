package trivyk8s

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// TrivyK8S interface represents the operations supported by the library
type TrivyK8S interface {
	Namespace(string) TrivyK8S
	ArtifactsK8S
}

// ArtifactsK8s interface represents operations to query the artifacts
type ArtifactsK8S interface {
	// ListArtifacts returns kubernetes scannable artifacs.
	ListArtifacts(context.Context) ([]*artifacts.Artifact, error)
}

type client struct {
	k8s       dynamic.Interface
	namespace string
}

// New creates a trivyK8S client
func New(k8sClient dynamic.Interface) TrivyK8S {
	return &client{k8s: k8sClient}
}

// Namespace configure the namespace to execute the queries
func (c *client) Namespace(namespace string) TrivyK8S {
	c.namespace = namespace
	return c
}

// ListArtifacts returns kubernetes scannable artifacs.
func (c *client) ListArtifacts(ctx context.Context) ([]*artifacts.Artifact, error) {
	grvs := k8s.GetGVRs(c.namespace)
	return c.listArtifacts(ctx, grvs)
}

func (c *client) listArtifacts(ctx context.Context, grvs []schema.GroupVersionResource) ([]*artifacts.Artifact, error) {
	artifactList := make([]*artifacts.Artifact, 0)

	for _, gvr := range grvs {
		var dclient dynamic.ResourceInterface
		if len(c.namespace) == 0 {
			dclient = c.k8s.Resource(gvr)
		} else {
			dclient = c.k8s.Resource(gvr).Namespace(c.namespace)
		}

		resources, err := dclient.List(ctx, v1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed listing resources for gvr: %v - %w", gvr, err)
		}

		for _, resource := range resources.Items {
			if ignoreResource(resource) {
				continue
			}
			artifact, err := artifacts.FromResource(resource)
			if err != nil {
				return nil, err
			}

			artifactList = append(artifactList, artifact)
		}
	}

	return artifactList, nil
}

// ignore resources to avoid duplication,
// when a resource has an owner, the image/iac will be scanned on the owner itself
func ignoreResource(resource unstructured.Unstructured) bool {
	switch resource.GetKind() {
	case k8s.KindPod, k8s.KindJob, k8s.KindReplicaSet:
		metadata := resource.GetOwnerReferences()
		if metadata != nil {
			return true
		}
	}

	return false
}
