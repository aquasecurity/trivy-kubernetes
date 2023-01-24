package trivyk8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/jobs"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k8s.io/client-go/dynamic"

	// import auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// TrivyK8S interface represents the operations supported by the library
type TrivyK8S interface {
	Namespace(string) TrivyK8S
	Resources(string) TrivyK8S
	ArtifactsK8S
}

// ArtifactsK8S interface represents operations to query the artifacts
type ArtifactsK8S interface {
	// ListArtifacts returns kubernetes scanable artifacts
	ListArtifacts(context.Context) ([]*artifacts.Artifact, error)
	// GetArtifact return kubernete scanable artifact
	GetArtifact(context.Context, string, string) (*artifacts.Artifact, error)
	// ListArtifactAndNodeInfo return kubernete scanable artifact and node info
	ListArtifactAndNodeInfo(context.Context) ([]*artifacts.Artifact, error)
}

type client struct {
	cluster   k8s.Cluster
	namespace string
	resources []string
	logger    *zap.SugaredLogger
}

// New creates a trivyK8S client
func New(cluster k8s.Cluster, logger *zap.SugaredLogger) TrivyK8S {
	return &client{cluster: cluster, logger: logger}
}

// Namespace configure the namespace to execute the queries
func (c *client) Namespace(namespace string) TrivyK8S {
	c.namespace = namespace
	return c
}

// Resource configure which resources to execute the queries
func (c *client) Resources(resources string) TrivyK8S {
	if len(resources) == 0 {
		return c
	}

	c.resources = strings.Split(resources, ",")

	return c
}

// ListArtifacts returns kubernetes scannable artifacs.
func (c *client) ListArtifacts(ctx context.Context) ([]*artifacts.Artifact, error) {
	artifactList := make([]*artifacts.Artifact, 0)

	namespaced := len(c.namespace) != 0
	grvs, err := c.cluster.GetGVRs(namespaced, c.resources)
	if err != nil {
		return nil, err
	}

	for _, gvr := range grvs {
		dclient := c.getDynamicClient(gvr)

		resources, err := dclient.List(ctx, v1.ListOptions{})
		if err != nil {
			lerr := fmt.Errorf("failed listing resources for gvr: %v - %w", gvr, err)

			if errors.IsNotFound(err) {
				c.logger.Error(lerr)
				// if a resource is not found, we log and continue
				continue
			}

			return nil, lerr
		}

		for _, resource := range resources.Items {
			if c.ignoreResource(resource) {
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

// ListArtifacts returns kubernetes scannable artifacs.
func (c *client) ListArtifactAndNodeInfo(ctx context.Context) ([]*artifacts.Artifact, error) {
	artifactList, err := c.ListArtifacts(ctx)
	if err != nil {
		return nil, err
	}
	labels := map[string]string{
		jobs.TrivyCollectorName: jobs.NodeCollectorName,
		jobs.TrivyAutoCreated:   "true",
	}
	jc := jobs.NewCollector(
		c.cluster,
		jobs.WithTimetout(time.Minute*5),
		jobs.WithJobTemplateName(jobs.NodeCollectorName),
		jobs.WithJobNamespace(jobs.TrivyNamespace),
		jobs.WithJobLabels(labels),
	)
	// delete trivy namespace
	defer jc.Cleanup(ctx)

	// collect node info
	for _, resource := range artifactList {
		if resource.Kind != "Node" {
			continue
		}
		nodeLabels := map[string]string{
			jobs.TrivyResourceName: resource.Name,
			jobs.TrivyResourceKind: resource.Kind,
		}
		// append node labels
		jc.AppendLabels(jobs.WithJobLabels(nodeLabels))
		output, err := jc.ApplyAndCollect(ctx, resource.Name)
		if err != nil {
			return nil, err
		}
		var nodeInfo map[string]interface{}
		err = json.Unmarshal([]byte(output), &nodeInfo)
		if err != nil {
			return nil, err
		}
		artifactList = append(artifactList, &artifacts.Artifact{Kind: "NodeInfo", Name: resource.Name, RawResource: nodeInfo})
	}
	return artifactList, err
}

// GetArtifact return kubernetes scannable artifac.
func (c *client) GetArtifact(ctx context.Context, kind, name string) (*artifacts.Artifact, error) {
	gvr, err := c.cluster.GetGVR(kind)
	if err != nil {
		return nil, err
	}

	dclient := c.getDynamicClient(gvr)
	resource, err := dclient.Get(ctx, name, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed getting resource for gvr: %v - %w", gvr, err)
	}

	artifact, err := artifacts.FromResource(*resource)
	if err != nil {
		return nil, err
	}

	return artifact, nil
}

func (c *client) getDynamicClient(gvr schema.GroupVersionResource) dynamic.ResourceInterface {
	dclient := c.cluster.GetDynamicClient()

	// don't use namespace if it is a cluster levle resource,
	// or namespace is empty
	if k8s.IsClusterResource(gvr) || len(c.namespace) == 0 {
		return dclient.Resource(gvr)
	}

	return dclient.Resource(gvr).Namespace(c.namespace)
}

// ignore resources to avoid duplication,
// when a resource has an owner, the image/iac will be scanned on the owner itself
func (c *client) ignoreResource(resource unstructured.Unstructured) bool {
	// if we are filtering resources, don't ignore
	if resource.GetKind() == "Node" {
		return false
	}
	if len(c.resources) > 0 {
		return false
	}

	for _, owner := range resource.GetOwnerReferences() {
		if k8s.IsBuiltInWorkload(&owner) {
			return true
		}
	}

	return false
}
