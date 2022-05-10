package k8s

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const (
	KindPod        = "Pod"
	KindJob        = "Job"
	KindCronJob    = "CronJob"
	KindReplicaSet = "ReplicaSet"

	AppsGroup              = "apps"
	BatchGroup             = "batch"
	RbacGroup              = "rbac.authorization.k8s.io"
	NetworkingGroup        = "networking.k8s.io"
	PolicyGroup            = "policy"
	V1Version              = "v1"
	V1beta1Version         = "v1beta1"
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
	PodSecurityPolicies    = "podsecuritypolicies"
)

// GetKubeConfig returns local kubernetes configurations
func GetKubeConfig() (*rest.Config, error) {
	return getConfigFlags().ToRESTConfig()
}

// GetCurrentContext returns local kubernetes current-context
func GetCurrentContext() (string, error) {
	cf := getConfigFlags()
	rawCfg, err := cf.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return "", err
	}
	return rawCfg.CurrentContext, nil
}

func getConfigFlags() *genericclioptions.ConfigFlags {
	return genericclioptions.NewConfigFlags(true)
}

// NewDynamicClient returns a dynamic k8s client
func NewDynamicClient(kubeConfig *rest.Config) (dynamic.Interface, error) {
	k8sClient, err := dynamic.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	return k8sClient, nil
}

// GetGVRs returns GroupVersionResource to query kubernetes,
// if the namespace is empty it returns GRVs for the whole cluster
func GetGVRs(namespace string) []schema.GroupVersionResource {
	gvrs := getNamespaceGVR()
	if len(namespace) == 0 {
		gvrs = append(gvrs, getClusterGVR()...)
	}
	return gvrs
}

func getClusterGVR() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{
			Version:  V1Version,
			Group:    RbacGroup,
			Resource: ClusterRoles,
		},
		{
			Version:  V1Version,
			Group:    RbacGroup,
			Resource: ClusterRoleBindings,
		},
		{
			Version:  V1beta1Version,
			Group:    PolicyGroup,
			Resource: PodSecurityPolicies,
		},
	}
}

func getNamespaceGVR() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: Deployments,
		},
		{
			Version:  V1Version,
			Group:    "",
			Resource: Pods,
		},
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: ReplicaSets,
		},
		{
			Version:  V1Version,
			Group:    "",
			Resource: ReplicationControllers,
		},
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: StatefulSets,
		},
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: DaemonSets,
		},
		{
			Version:  V1Version,
			Group:    BatchGroup,
			Resource: CronJobs,
		},
		{
			Version:  V1Version,
			Group:    BatchGroup,
			Resource: Jobs,
		},
		{
			Version:  V1Version,
			Group:    "",
			Resource: Services,
		},
		{
			Version:  V1Version,
			Group:    "",
			Resource: ConfigMaps,
		},
		{
			Version:  V1Version,
			Group:    RbacGroup,
			Resource: Roles,
		},
		{
			Version:  V1Version,
			Group:    RbacGroup,
			Resource: RoleBindings,
		},
		{
			Version:  V1Version,
			Group:    NetworkingGroup,
			Resource: NetworkPolicys,
		},
		{
			Version:  V1Version,
			Group:    NetworkingGroup,
			Resource: Ingresss,
		},
		{
			Version:  V1Version,
			Group:    "",
			Resource: ResourceQuotas,
		},
		{
			Version:  V1Version,
			Group:    "",
			Resource: LimitRanges,
		},
	}
}
