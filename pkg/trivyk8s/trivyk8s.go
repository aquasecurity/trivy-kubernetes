package trivyk8s

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/bom"
	"github.com/aquasecurity/trivy-kubernetes/pkg/jobs"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k8s.io/client-go/dynamic"

	// import auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// TrivyK8S interface represents the operations supported by the library
type TrivyK8S interface {
	Namespace(string) TrivyK8S
	AllNamespaces() TrivyK8S
	Resources(string) TrivyK8S
	ArtifactsK8S
}

// ArtifactsK8S interface represents operations to query the artifacts
type ArtifactsK8S interface {
	// ListArtifacts returns kubernetes scanable artifacts
	ListArtifacts(context.Context) ([]*artifacts.Artifact, error)
	// ListArtifactAndNodeInfo return kubernete scanable artifact and node info
	ListArtifactAndNodeInfo(context.Context, ...NodeCollectorOption) ([]*artifacts.Artifact, error)
	// ListClusterBomInfo returns kubernetes Bom (node,core components) information.
	ListClusterBomInfo(context.Context) ([]*artifacts.Artifact, error)
}

type client struct {
	cluster              k8s.Cluster
	namespace            string
	resources            []string
	allNamespaces        bool
	excludeOwned         bool
	scanJobParams        scanJobParams
	nodeConfig           bool // feature flag to enable/disable node config collection
	excludeKinds         []string
	includeKinds         []string
	excludeNamespaces    []string
	includeNamespaces    []string
	commandPaths         []string
	specCommandIds       []string
	commandFilesystem    embed.FS
	nodeConfigFilesystem embed.FS
}

type K8sOption func(*client)

func WithExcludeOwned(excludeOwned bool) K8sOption {
	return func(c *client) {
		c.excludeOwned = excludeOwned
	}
}
func WithExcludeKinds(excludeKinds []string) K8sOption {
	return func(c *client) {
		for _, kind := range excludeKinds {
			c.excludeKinds = append(c.excludeKinds, strings.ToLower(kind))
		}
	}
}
func WithIncludeKinds(includeKinds []string) K8sOption {
	return func(c *client) {
		for _, kind := range includeKinds {
			c.includeKinds = append(c.includeKinds, strings.ToLower(kind))
		}
	}
}

func WithExcludeNamespaces(excludeNamespaces []string) K8sOption {
	return func(c *client) {
		for _, ns := range excludeNamespaces {
			c.excludeNamespaces = append(c.excludeNamespaces, strings.ToLower(ns))
		}
	}
}
func WithIncludeNamespaces(includeNamespaces []string) K8sOption {
	return func(c *client) {
		for _, ns := range includeNamespaces {
			c.includeNamespaces = append(c.includeNamespaces, strings.ToLower(ns))
		}
	}
}

// New creates a trivyK8S client
func New(cluster k8s.Cluster, opts ...K8sOption) TrivyK8S {
	c := &client{
		cluster: cluster,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Namespace configure the namespace to execute the queries
func (c *client) Namespace(namespace string) TrivyK8S {
	c.namespace = namespace
	return c
}

// Namespace configure the namespace to execute the queries
func (c *client) AllNamespaces() TrivyK8S {
	c.allNamespaces = true
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

func isNamespaced(namespace string, allNamespace bool) bool {
	if len(namespace) != 0 || (len(namespace) == 0 && allNamespace) {
		return true
	}
	return false
}

// return list of namespaces to exclude
func (c *client) GetExcludeNamespaces() []string {
	return c.excludeNamespaces
}

// return list of namespaces to include
func (c *client) GetIncludeNamespaces() []string {
	return c.includeNamespaces
}

// return list of kinds to exclude
func (c *client) GetExcludeKinds() []string {
	return c.excludeKinds
}

// return list of kinds to include
func (c client) GetIncludeKinds() []string {
	return c.includeKinds
}

// ListArtifacts returns kubernetes scannable artifacs.
func (c *client) ListArtifacts(ctx context.Context) ([]*artifacts.Artifact, error) {
	artifactList := make([]*artifacts.Artifact, 0)

	namespaced := isNamespaced(c.namespace, c.allNamespaces)
	grvs, err := c.cluster.GetGVRs(namespaced, c.resources)
	if err != nil {
		return nil, err
	}

	for _, gvr := range grvs {
		dclient := c.getDynamicClient(gvr)

		resources, err := dclient.List(ctx, v1.ListOptions{})
		if err != nil {
			lerr := fmt.Errorf("failed listing resources for gvr: %v - %w", gvr, err)

			if errors.IsNotFound(err) || errors.IsForbidden(err) {
				slog.Error("Unable to list resources", "error", lerr)
				continue
			}

			return nil, lerr
		}

		for _, resource := range resources.Items {
			if c.ignoreResource(resource) {
				continue
			}

			// if excludeOwned is enabled and the resource is owned by built-in workload, then we skip it
			if c.excludeOwned && c.hasOwner(resource) {
				continue
			}
			// filter resources by kind
			if FilterResources(c.includeKinds, c.excludeKinds, resource.GetKind()) {
				continue
			}

			// filter resources by namespace
			if FilterResources(c.includeNamespaces, c.excludeNamespaces, resource.GetNamespace()) {
				continue
			}

			lastAppliedResource := resource
			if jsonManifest, ok := resource.GetAnnotations()["kubectl.kubernetes.io/last-applied-configuration"]; ok { // required for outdated-api when k8s convert resources
				err := json.Unmarshal([]byte(jsonManifest), &lastAppliedResource)
				if err != nil {
					continue
				}
			}
			auths, err := c.cluster.AuthByResource(lastAppliedResource)
			if err != nil {
				return nil, fmt.Errorf("failed getting auth for gvr: %v - %w", gvr, err)
			}
			artifact, err := artifacts.FromResource(lastAppliedResource, auths)
			if err != nil {
				return nil, err
			}

			artifactList = append(artifactList, artifact)
		}
	}
	if !namespaced {
		bomArtifacts, err := c.ListClusterBomInfo(ctx)
		if err != nil {
			return nil, err
		}
		artifactList = append(artifactList, bomArtifacts...)
	}
	return artifactList, nil
}

func FilterResources(include []string, exclude []string, key string) bool {

	if (len(include) > 0 && len(exclude) > 0) || // if both include and exclude cannot be set together
		(len(include) == 0 && len(exclude) == 0) {
		return false
	}
	if len(exclude) > 0 {
		if slices.Contains(exclude, strings.ToLower(key)) {
			return true
		}
	} else if len(include) > 0 {
		if !slices.Contains(include, strings.ToLower(key)) {
			return true
		}
	}

	return false
}

type scanJobParams struct {
	affinity         *corev1.Affinity
	tolerations      []corev1.Toleration
	ignoreLabels     map[string]string
	scanJobNamespace string
	imageRef         string
}

type NodeCollectorOption func(*client)

func WithAffinity(affinity *corev1.Affinity) NodeCollectorOption {
	return func(c *client) {
		c.scanJobParams.affinity = affinity
	}
}

func WithTolerations(tolerations []corev1.Toleration) NodeCollectorOption {
	return func(c *client) {
		c.scanJobParams.tolerations = tolerations
	}
}

func WithIgnoreLabels(ignoreLabels map[string]string) NodeCollectorOption {
	return func(c *client) {
		c.scanJobParams.ignoreLabels = ignoreLabels
	}
}

func WithScanJobNamespace(namespace string) NodeCollectorOption {
	return func(c *client) {
		c.scanJobParams.scanJobNamespace = namespace
	}
}

func WithScanJobImageRef(imageRef string) NodeCollectorOption {
	return func(c *client) {
		c.scanJobParams.imageRef = imageRef
	}
}

func WithNodeConfig(nodeConfig bool) NodeCollectorOption {
	return func(c *client) {
		c.nodeConfig = nodeConfig
	}
}
func WithCommandPaths(commandPaths []string) NodeCollectorOption {
	return func(c *client) {
		c.commandPaths = commandPaths
	}
}

func WithEmbeddedCommandFileSystem(commandsFileSystem embed.FS) NodeCollectorOption {
	return func(c *client) {
		c.commandFilesystem = commandsFileSystem
	}
}

func WithEmbeddedNodeConfigFilesystem(nodeConfigFileSystem embed.FS) NodeCollectorOption {
	return func(c *client) {
		c.nodeConfigFilesystem = nodeConfigFileSystem
	}
}
func WithSpecCommandIds(specCommandIds []string) NodeCollectorOption {
	return func(c *client) {
		c.specCommandIds = specCommandIds
	}
}

// ListArtifacts returns kubernetes scannable artifacs.
func (c *client) ListArtifactAndNodeInfo(ctx context.Context,
	opts ...NodeCollectorOption) ([]*artifacts.Artifact, error) {
	for _, opt := range opts {
		opt(c)
	}
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
		jobs.WithJobNamespace(c.scanJobParams.scanJobNamespace),
		jobs.WithJobLabels(labels),
		jobs.WithImageRef(c.scanJobParams.imageRef),
		jobs.WithJobAffinity(c.scanJobParams.affinity),
		jobs.WithJobTolerations(c.scanJobParams.tolerations),
		jobs.WithNodeConfig(c.nodeConfig),
		jobs.WithCommandsPath(c.commandPaths),
		jobs.WithSpecCommands(c.specCommandIds),
		jobs.WithEmbeddedCommandFileSystem(c.commandFilesystem),
		jobs.WithEmbeddedNodeConfigFilesystem(c.nodeConfigFilesystem),
	)
	// delete trivy namespace
	defer jc.Cleanup(ctx)

	// collect node info
	for _, resource := range artifactList {
		if resource.Kind != "Node" {
			continue
		}
		if ignoreNodeByLabel(resource, c.scanJobParams.ignoreLabels) {
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
		artifactList = append(artifactList, &artifacts.Artifact{
			Kind:        "NodeInfo",
			Name:        resource.Name,
			RawResource: nodeInfo,
		})
	}
	return artifactList, err
}

// ListClusterBomInfo returns kubernetes Bom (node,core components and etc) information.
func (c *client) ListClusterBomInfo(ctx context.Context) ([]*artifacts.Artifact, error) {

	b, err := c.cluster.CreateClusterBom(ctx)
	if err != nil {
		return []*artifacts.Artifact{}, err
	}
	b.Components = c.filterNamespaces(b.Components)
	if slices.Contains(c.GetExcludeKinds(), "node") {
		b.NodesInfo = []bom.NodeInfo{}
	}
	return BomToArtifacts(b)
}

func (c *client) filterNamespaces(comp []bom.Component) []bom.Component {
	bm := make([]bom.Component, 0)
	for _, co := range comp {
		if FilterResources(c.GetIncludeNamespaces(), c.GetExcludeNamespaces(), co.Namespace) {
			continue
		}
		bm = append(bm, co)
	}
	return bm
}

func BomToArtifacts(b *bom.Result) ([]*artifacts.Artifact, error) {
	artifactList := make([]*artifacts.Artifact, 0)
	for _, c := range b.Components {
		rawResource, err := rawResource(&c)
		if err != nil {
			return []*artifacts.Artifact{}, err
		}
		artifactList = append(artifactList, &artifacts.Artifact{
			Kind:        "ControlPlaneComponents",
			Namespace:   c.Namespace,
			Name:        c.Name,
			RawResource: rawResource,
		})
	}
	for _, ni := range b.NodesInfo {
		rawResource, err := rawResource(&ni)
		if err != nil {
			return []*artifacts.Artifact{}, err
		}
		artifactList = append(artifactList, &artifacts.Artifact{
			Kind:        "NodeComponents",
			Name:        ni.NodeName,
			RawResource: rawResource,
		})
	}
	cr, err := rawResource(&bom.Result{
		ID:         b.ID,
		Type:       "ClusterInfo",
		Version:    b.Version,
		Properties: b.Properties,
	})
	if err != nil {
		return []*artifacts.Artifact{}, err
	}
	artifactList = append(artifactList, &artifacts.Artifact{
		Kind:        "Cluster",
		Name:        b.ID,
		RawResource: cr,
	})
	return artifactList, nil
}

func rawResource(resource interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(resource)
	if err != nil {
		return nil, err
	}
	var rawResource map[string]interface{}
	err = json.Unmarshal(b, &rawResource)
	if err != nil {
		return nil, err
	}
	return rawResource, nil
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
		return isNodeStatusUnknown(resource)
	}

	if len(c.resources) > 0 {
		return false
	}

	return c.hasOwner(resource)
}

func (c *client) hasOwner(resource unstructured.Unstructured) bool {
	for _, owner := range resource.GetOwnerReferences() {
		if k8s.IsBuiltInWorkload(&owner) {
			return true
		}
	}

	return false
}

// isNodeStatusUnknown check weathre the node status is Ready otherwise ignore it
func isNodeStatusUnknown(resource unstructured.Unstructured) bool {
	var node corev1.Node
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(resource.Object, &node)
	if err != nil {
		return true
	}
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			if condition.Status == corev1.ConditionTrue {
				return false
			}
		}
	}
	return true
}

func ignoreNodeByLabel(resource *artifacts.Artifact, ignoreLabels map[string]string) bool {
	if len(ignoreLabels) == 0 {
		return false
	}
	var matchingLabels int
	for key, val := range ignoreLabels {
		if lVal, ok := resource.Labels[key]; ok && lVal == val {
			matchingLabels++
		}
	}
	return matchingLabels == len(ignoreLabels)
}
