package k8s

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-kubernetes/pkg/bom"
	containerimage "github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	k8sapierror "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/strings/slices"
)

const (
	KindPod                   = "Pod"
	KindJob                   = "Job"
	KindCronJob               = "CronJob"
	KindReplicaSet            = "ReplicaSet"
	KindReplicationController = "ReplicationController"
	KindStatefulSet           = "StatefulSet"
	KindDaemonSet             = "DaemonSet"
	KindDeployment            = "Deployment"

	Deployments            = "deployments"
	ReplicaSets            = "replicasets"
	ReplicationControllers = "replicationcontrollers"
	StatefulSets           = "statefulsets"
	DaemonSets             = "daemonsets"
	CronJobs               = "cronjobs"
	Services               = "services"
	ServiceAccounts        = "serviceaccounts"
	Jobs                   = "jobs"
	Pods                   = "pods"
	ConfigMaps             = "configmaps"
	Roles                  = "roles"
	RoleBindings           = "rolebindings"
	NetworkPolicys         = "networkpolicies"
	Ingresss               = "ingresses"
	ResourceQuotas         = "resourcequotas"
	LimitRanges            = "limitranges"
	ClusterRoles           = "clusterroles"
	ClusterRoleBindings    = "clusterrolebindings"
	Nodes                  = "nodes"
	k8sComponentNamespace  = "kube-system"
)

// Cluster interface represents the operations needed to scan a cluster
type Cluster interface {
	// GetCurrentContext returns local kubernetes current-context
	GetCurrentContext() string
	// GetCurrentNamespace returns local kubernetes current namespace
	GetCurrentNamespace() string
	// GetDynamicClient returns a dynamic k8s client
	GetDynamicClient() dynamic.Interface
	// GetK8sClientSet returns a k8s client set
	GetK8sClientSet() *kubernetes.Clientset
	// GetGVRs returns cluster GroupVersionResource to query kubernetes, receives
	// a boolean to determine if returns namespaced GVRs only or all GVRs, unless
	// resources is passed to filter
	GetGVRs(bool, []string) ([]schema.GroupVersionResource, error)
	// GetGVR returns resource GroupVersionResource to query kubernetes, receives
	// a string with the resource kind
	GetGVR(string) (schema.GroupVersionResource, error)
	// CreatePkgBom returns a k8s client set
	CreateClusterBom(ctx context.Context) (*bom.Result, error)
}

type cluster struct {
	currentContext   string
	currentNamespace string
	dynamicClient    dynamic.Interface
	restMapper       meta.RESTMapper
	clientset        *kubernetes.Clientset
	cConfig          clientcmd.ClientConfig
}

type ClusterOption func(*genericclioptions.ConfigFlags)

// Specify the context to use, if empty uses default
func WithContext(context string) ClusterOption {
	return func(c *genericclioptions.ConfigFlags) {
		c.Context = &context
	}
}

// kubeconfig can be used to specify the config file path (overrides KUBECONFIG env)
func WithKubeConfig(kubeConfig string) ClusterOption {
	return func(c *genericclioptions.ConfigFlags) {
		c.KubeConfig = &kubeConfig
	}
}

// GetCluster returns a current configured cluster,
func GetCluster(opts ...ClusterOption) (Cluster, error) {
	cf := genericclioptions.NewConfigFlags(true)
	for _, opt := range opts {
		opt(cf)
	}

	// disable warnings
	rest.SetDefaultWarningHandler(rest.NoWarnings{})

	clientConfig := cf.ToRawKubeConfigLoader()

	restMapper, err := cf.ToRESTMapper()
	if err != nil {
		return nil, err
	}

	return getCluster(clientConfig, restMapper, *cf.Context)
}

func getCluster(clientConfig clientcmd.ClientConfig, restMapper meta.RESTMapper, currentContext string) (*cluster, error) {
	kubeConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	k8sDynamicClient, err := dynamic.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	var kubeClientset *kubernetes.Clientset

	kubeClientset, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	rawCfg, err := clientConfig.RawConfig()
	if err != nil {
		return nil, err
	}

	var namespace string

	if len(currentContext) == 0 {
		currentContext = rawCfg.CurrentContext
	}
	if context, ok := rawCfg.Contexts[currentContext]; ok {
		namespace = context.Namespace
	}

	if len(namespace) == 0 {
		namespace = "default"
	}

	return &cluster{
		currentContext:   currentContext,
		currentNamespace: namespace,
		dynamicClient:    k8sDynamicClient,
		restMapper:       restMapper,
		clientset:        kubeClientset,
		cConfig:          clientConfig,
	}, nil
}

// GetCurrentContext returns local kubernetes current-context
func (c *cluster) GetCurrentContext() string {
	return c.currentContext
}

// GetCurrentNamespace returns local kubernetes current namespace
func (c *cluster) GetCurrentNamespace() string {
	return c.currentNamespace
}

// GetDynamicClient returns a dynamic k8s client
func (c *cluster) GetDynamicClient() dynamic.Interface {
	return c.dynamicClient
}

// GetK8sClientSet returns k8s clientSet
func (c *cluster) GetK8sClientSet() *kubernetes.Clientset {
	return c.clientset
}

// GetGVRs returns cluster GroupVersionResource to query kubernetes, receives
// a boolean to determine if returns namespaced GVRs only or all GVRs, unless
// resources is passed to filter
func (c *cluster) GetGVRs(namespaced bool, resources []string) ([]schema.GroupVersionResource, error) {
	grvs := make([]schema.GroupVersionResource, 0)
	if len(resources) == 0 {
		resources = getNamespaceResources()
		if !namespaced {
			resources = append(resources, getClusterResources()...)
		}
	}
	for _, resource := range resources {
		gvr, err := c.GetGVR(resource)
		if err != nil {
			return nil, err
		}

		grvs = append(grvs, gvr)
	}

	return grvs, nil
}

func (c *cluster) GetGVR(kind string) (schema.GroupVersionResource, error) {
	return c.restMapper.ResourceFor(schema.GroupVersionResource{Resource: kind})
}

// IsClusterResource returns if a GVR is a cluster resource
func IsClusterResource(gvr schema.GroupVersionResource) bool {
	for _, r := range getClusterResources() {
		if gvr.Resource == r {
			return true
		}
	}
	return false
}

// IsBuiltInWorkload returns true if the specified v1.OwnerReference
// is a built-in Kubernetes workload, false otherwise.
func IsBuiltInWorkload(resource *metav1.OwnerReference) bool {
	return resource != nil &&
		(resource.Kind == string(KindReplicaSet) ||
			resource.Kind == string(KindReplicationController) ||
			resource.Kind == string(KindStatefulSet) ||
			resource.Kind == string(KindDeployment) ||
			resource.Kind == string(KindCronJob) ||
			resource.Kind == string(KindDaemonSet) ||
			resource.Kind == string(KindJob))
}

func getClusterResources() []string {
	return []string{
		ClusterRoles,
		ClusterRoleBindings,
		Nodes,
	}
}

func getNamespaceResources() []string {
	return []string{
		Deployments,
		Pods,
		ReplicaSets,
		ReplicationControllers,
		StatefulSets,
		DaemonSets,
		CronJobs,
		Jobs,
		Services,
		ServiceAccounts,
		ConfigMaps,
		Roles,
		RoleBindings,
		NetworkPolicys,
		Ingresss,
		ResourceQuotas,
		LimitRanges,
	}
}

func (c *cluster) CreateClusterBom(ctx context.Context) (*bom.Result, error) {
	// collect addons info
	var components []bom.Component
	labels := map[string]string{
		k8sComponentNamespace: "component",
	}
	if c.isOpenShift() {
		labels = map[string]string{
			"openshift-kube-apiserver":          "apiserver",
			"openshift-kube-controller-manager": "kube-controller-manager",
			"openshift-kube-scheduler":          "scheduler",
			"openshift-etcd":                    "etcd",
		}
	}
	components, err := c.collectComponents(ctx, labels, "control_plane_component")
	if err != nil {
		return nil, err
	}
	addonLabels := map[string]string{
		k8sComponentNamespace: "k8s-app",
	}
	addons, err := c.collectComponents(ctx, addonLabels, "addons")
	if err != nil {
		return nil, err
	}
	components = append(components, addons...)
	nodesInfo, err := c.CollectNodes(components)
	if err != nil {
		return nil, err
	}
	return c.getClusterBomInfo(components, nodesInfo)
}

func (c *cluster) GetContainer(imageRef containerimage.Reference, imageName containerimage.Reference) (bom.Container, error) {
	repoName := imageRef.Context().RepositoryStr()
	registryName := imageRef.Context().RegistryStr()
	if strings.HasPrefix(repoName, "library/sha256") {
		repoName = imageName.Context().RepositoryStr()
		registryName = imageName.Context().RegistryStr()
	}

	return bom.Container{
		Repository: repoName,
		Registry:   registryName,
		ID:         fmt.Sprintf("%s:%s", repoName, imageName.Identifier()),
		Digest:     imageRef.Context().Digest(imageRef.Identifier()).DigestStr(),
		Version:    imageName.Identifier(),
	}, nil
}

func (c *cluster) CollectNodes(components []bom.Component) ([]bom.NodeInfo, error) {
	nodes, err := c.clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []bom.NodeInfo{}, err
	}
	nodesInfo := make([]bom.NodeInfo, 0)
	for _, node := range nodes.Items {
		nodeRole := "worker"
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
			nodeRole = "master"
		}
		if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
			nodeRole = "master"
		}
		images := make([]string, 0)
		for _, image := range node.Status.Images {
			for _, c := range components {
				for _, co := range c.Containers {
					id := fmt.Sprintf("%s/%s:%s", co.Registry, co.Repository, co.Version)
					if slices.Contains(image.Names, id) {
						images = append(images, id)
					}
				}
			}
		}
		nodesInfo = append(nodesInfo, bom.NodeInfo{
			NodeName:                node.Name,
			KubeletVersion:          node.Status.NodeInfo.KubeletVersion,
			ContainerRuntimeVersion: node.Status.NodeInfo.ContainerRuntimeVersion,
			OsImage:                 node.Status.NodeInfo.OSImage,
			KubeProxyVersion:        node.Status.NodeInfo.KernelVersion,
			Properties: map[string]string{
				"node_role":        nodeRole,
				"host_name":        node.ObjectMeta.Name,
				"kernel_version":   node.Status.NodeInfo.KernelVersion,
				"operating_system": node.Status.NodeInfo.OperatingSystem,
				"architecture":     node.Status.NodeInfo.Architecture,
			},
			Images: images,
		})
	}
	return nodesInfo, nil
}

func getPodsInfo(ctx context.Context, clientset *kubernetes.Clientset, labelSelector string, namespace string) (*corev1.PodList, error) {
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return nil, err
	}
	return pods, nil
}

func (c *cluster) collectComponents(ctx context.Context, labels map[string]string, propertyKey string) ([]bom.Component, error) {
	components := make([]bom.Component, 0)
	for namespace, labelSelector := range labels {
		pods, err := getPodsInfo(ctx, c.clientset, labelSelector, namespace)
		if err != nil {
			continue
		}
		for _, pod := range pods.Items {
			containers := make([]bom.Container, 0)
			for _, s := range pod.Status.ContainerStatuses {
				imageRef, err := containerimage.ParseReference(s.ImageID)
				if err != nil {
					return nil, err
				}
				imageName, err := containerimage.ParseReference(s.Image)
				if err != nil {
					return nil, err
				}
				c, err := c.GetContainer(imageRef, imageName)
				if err != nil {
					continue
				}
				containers = append(containers, c)
			}
			props := make(map[string]string)
			if componentValue, ok := pod.GetLabels()[labelSelector]; ok {
				props[propertyKey] = componentValue
			}
			components = append(components, bom.Component{
				Namespace:  pod.Namespace,
				Name:       pod.Name,
				Properties: props,
				Containers: containers,
			})
		}
	}
	return components, nil
}

func (c *cluster) isOpenShift() bool {
	ctx := context.Background()
	_, err := c.clientset.CoreV1().Namespaces().Get(ctx, "openshift-kube-apiserver", metav1.GetOptions{})
	return !k8sapierror.IsNotFound(err)
}

func (c *cluster) getClusterBomInfo(components []bom.Component, nodeInfo []bom.NodeInfo) (*bom.Result, error) {
	name, version, err := c.ClusterNameVersion()
	if err != nil {
		return nil, err
	}
	br := &bom.Result{
		Components: components,
		ID:         fmt.Sprintf("%s@%s", name, version),
		Type:       "Cluster",
		NodesInfo:  nodeInfo,
	}
	return br, nil
}

func (c *cluster) ClusterNameVersion() (string, string, error) {
	rawCfg, err := c.cConfig.RawConfig()
	if err != nil {
		return "", "", err
	}
	clusterName := rawCfg.Contexts[rawCfg.CurrentContext].Cluster
	version, err := c.clientset.ServerVersion()
	if err != nil {
		return "", "", err
	}
	return clusterName, version.GitVersion, nil
}
