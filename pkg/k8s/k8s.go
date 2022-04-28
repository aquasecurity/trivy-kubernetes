package k8s

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	KindPod     = "Pod"
	KindJob     = "Job"
	KindCronJob = "CronJob"

	AppsGroup              = "apps"
	CoreGroup              = "cores"
	BatchGroup             = "batch"
	RbacGroup              = "rbac"
	NetworkingGroup        = "networking"
	V1Version              = "v1"
	V1beta1Version         = "v1Beta1"
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
	NetworkPolicys         = "networkpolicy"
	Ingresss               = "ingresss"
	ResourceQuotas         = "resourceQuotas"
	LimitRanges            = "limitranges"
)

func GetGVRs(namespace string) []schema.GroupVersionResource {
	return getNamespaceGVR()
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
			Version:  "v1",
			Group:    BatchGroup,
			Resource: CronJobs,
		},
		{
			Version:  V1Version,
			Group:    BatchGroup,
			Resource: Jobs,
		},
		//		{
		//			Version:  V1Version,
		//			Group:    "svc",
		//			Resource: Services,
		//		},
		// {
		// 	Version:  V1Version,
		// 	Group:    "cm",
		// 	Resource: ConfigMaps,
		// },
		// {
		// 	Version:  V1Version,
		// 	Group:    RbacGroup,
		// 	Resource: Roles,
		// },
		// {
		// 	Version:  V1Version,
		// 	Group:    RbacGroup,
		// 	Resource: RoleBindings,
		// },
		// {
		// 	Version:  V1Version,
		// 	Group:    NetworkingGroup,
		// 	Resource: NetworkPolicys,
		// },
		// {
		// 	Version:  V1Version,
		// 	Group:    NetworkingGroup,
		// 	Resource: Ingresss,
		// },
		// {
		// 	Version:  V1Version,
		// 	Group:    CoreGroup,
		// 	Resource: ResourceQuotas,
		// },
		// {
		// 	Version:  V1Version,
		// 	Group:    CoreGroup,
		// 	Resource: LimitRanges,
		// },
	}
}
