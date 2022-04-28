package trivyk8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

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

type TrivyK8S interface {
	ListArtifacts(context.Context, string) ([]*artifacts.Artifact, error)
}

type client struct {
	k8s dynamic.Interface
}

func New(kubeConfig *rest.Config) (TrivyK8S, error) {
	k8sClient, err := dynamic.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	return &client{k8sClient}, nil
}

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
			// it should return artifact, found, error
			artifact, err := artifacts.FromResource(resource)
			if err != nil {
				return nil, err
			}

			if artifact == nil {
				continue
			}

			artifactList = append(artifactList, artifact)
		}
	}

	return artifactList, nil
}
