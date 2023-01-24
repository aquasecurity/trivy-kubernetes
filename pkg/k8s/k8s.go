package k8s

import (
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
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
}

type cluster struct {
	currentContext   string
	currentNamespace string
	dynamicClient    dynamic.Interface
	restMapper       meta.RESTMapper
	clientset        *kubernetes.Clientset
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

	return getCluster(clientConfig, restMapper)
}

func getCluster(clientConfig clientcmd.ClientConfig, restMapper meta.RESTMapper) (*cluster, error) {
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
	if context, ok := rawCfg.Contexts[rawCfg.CurrentContext]; ok {
		namespace = context.Namespace
	}

	if len(namespace) == 0 {
		namespace = "default"
	}

	return &cluster{
		currentContext:   rawCfg.CurrentContext,
		currentNamespace: namespace,
		dynamicClient:    k8sDynamicClient,
		restMapper:       restMapper,
		clientset:        kubeClientset,
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
func IsBuiltInWorkload(resource *v1.OwnerReference) bool {
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
		ConfigMaps,
		Roles,
		RoleBindings,
		NetworkPolicys,
		Ingresss,
		ResourceQuotas,
		LimitRanges,
	}
}
