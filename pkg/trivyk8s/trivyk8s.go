package trivyk8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// GetKubeConfig returns local kubernetes configurations
func GetKubeConfig() (*rest.Config, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	kubeConfigPath := filepath.Join(userHomeDir, ".kube", "config")
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, err
	}

	return kubeConfig, nil
}

// TrivyK8S interface represents the operations supported by the library
type TrivyK8S interface {
	ListArtifacts(context.Context, string) ([]*artifacts.Artifact, error)
}

type client struct {
	k8s dynamic.Interface
}

// New creates a trivyK8S client
func New(kubeConfig *rest.Config) (TrivyK8S, error) {
	k8sClient, err := dynamic.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	return &client{k8sClient}, nil
}

// ListArtifacts returns kubernetes scannable artifacs. If namespace is empty, it returns artifacts
// for the whole cluster.
func (c *client) ListArtifacts(ctx context.Context, namespace string) ([]*artifacts.Artifact, error) {
	artifactList := make([]*artifacts.Artifact, 0)

	for _, gvr := range k8s.GetGVRs(namespace) {
		var dclient dynamic.ResourceInterface
		if len(namespace) == 0 {
			dclient = c.k8s.Resource(gvr)
		} else {
			dclient = c.k8s.Resource(gvr).Namespace(namespace)
		}

		resources, err := dclient.List(ctx, v1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("can't list resource %v - %v", gvr, err)
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
