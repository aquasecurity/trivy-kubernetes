package k8s

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-kubernetes/pkg/bom"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s/docker"
	"github.com/aquasecurity/trivy-kubernetes/utils"
	containerimage "github.com/google/go-containerregistry/pkg/name"
	ms "github.com/mitchellh/mapstructure"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	k8sapierror "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/strings/slices"
)

var (
	UpstreamOrgName = map[string]string{
		"k8s.io":      "controller-manager,kubelet,apiserver,kubectl,kubernetes,kube-scheduler,kube-proxy",
		"sigs.k8s.io": "secrets-store-csi-driver",
		"go.etcd.io":  "etcd/v3",
	}

	UpstreamRepoName = map[string]string{
		"kube-controller-manager":  "controller-manager",
		"kubelet":                  "kubelet",
		"kube-apiserver":           "apiserver",
		"kubectl":                  "kubectl",
		"kubernetes":               "kubernetes",
		"kube-scheduler":           "kube-scheduler",
		"kube-proxy":               "kube-proxy",
		"api server":               "apiserver",
		"etcd":                     "etcd/v3",
		"secrets-store-csi-driver": "secrets-store-csi-driver",
	}
	CoreComponentPropertyType = map[string]string{
		"controller-manager": "controlPlane",
		"apiserver":          "controlPlane",
		"kube-scheduler":     "controlPlane",
		"etcd/v3":            "controlPlane",
		"kube-proxy":         "node",
	}
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

	serviceAccountDefault = "default"
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
	// GetClusterVersion return cluster git version
	GetClusterVersion() string
	// AuthByResource return image pull secrets by resource pod spec
	AuthByResource(resource unstructured.Unstructured) (map[string]docker.Auth, error)
}

type cluster struct {
	currentContext   string
	currentNamespace string
	serverVersion    string
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

	return getCluster(clientConfig, restMapper, *cf.Context, false)
}

func getCluster(clientConfig clientcmd.ClientConfig, restMapper meta.RESTMapper, currentContext string, fakeConfig bool) (*cluster, error) {
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
	var serverVersion string
	if !fakeConfig {
		sv, err := kubeClientset.ServerVersion()
		if err != nil {
			return nil, err
		}
		serverVersion = strings.TrimPrefix(sv.GitVersion, "v")
	}
	return &cluster{
		currentContext:   currentContext,
		currentNamespace: namespace,
		dynamicClient:    k8sDynamicClient,
		restMapper:       restMapper,
		clientset:        kubeClientset,
		cConfig:          clientConfig,
		serverVersion:    serverVersion,
	}, nil
}

// GetCurrentContext returns local kubernetes current-context
func (c *cluster) GetCurrentContext() string {
	return c.currentContext
}

// GetClusterVersion return cluster git version
func (c *cluster) GetClusterVersion() string {
	return c.serverVersion
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
		"": "component",
	}
	if c.isOpenShift() {
		labels = map[string]string{
			"openshift-kube-apiserver":          "apiserver",
			"openshift-kube-controller-manager": "kube-controller-manager",
			"openshift-kube-scheduler":          "scheduler",
			"openshift-etcd":                    "etcd",
		}
	}
	components, err := c.collectComponents(ctx, labels)
	if err != nil {
		return nil, err
	}
	addonLabels := map[string]string{
		k8sComponentNamespace: "k8s-app",
	}
	addons, err := c.collectComponents(ctx, addonLabels)
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

func GetContainer(imageRef containerimage.Reference, imageName containerimage.Reference) (bom.Container, error) {
	repoName := imageName.Context().RepositoryStr()
	registryName := imageName.Context().RegistryStr()

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
		nf := NodeInfo(node)
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
		nf.Images = images
		nodesInfo = append(nodesInfo, nf)
	}
	return nodesInfo, nil
}

func NodeInfo(node v1.Node) bom.NodeInfo {
	nodeRole := "worker"
	if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
		nodeRole = "master"
	}
	if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
		nodeRole = "master"
	}
	return bom.NodeInfo{
		NodeName:                node.Name,
		KubeletVersion:          node.Status.NodeInfo.KubeletVersion,
		ContainerRuntimeVersion: node.Status.NodeInfo.ContainerRuntimeVersion,
		OsImage:                 node.Status.NodeInfo.OSImage,
		KubeProxyVersion:        node.Status.NodeInfo.KubeProxyVersion,
		Properties: map[string]string{
			"NodeRole":        nodeRole,
			"HostName":        node.ObjectMeta.Name,
			"KernelVersion":   node.Status.NodeInfo.KernelVersion,
			"OperatingSystem": node.Status.NodeInfo.OperatingSystem,
			"Architecture":    node.Status.NodeInfo.Architecture,
		},
	}
}

func getPodsInfo(ctx context.Context, clientset *kubernetes.Clientset, labelSelector string, namespace string) (*corev1.PodList, error) {
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return nil, err
	}
	return pods, nil
}

func (c *cluster) collectComponents(ctx context.Context, labels map[string]string) ([]bom.Component, error) {
	components := make([]bom.Component, 0)
	for namespace, labelSelector := range labels {
		pods, err := getPodsInfo(ctx, c.clientset, labelSelector, namespace)
		if err != nil {
			continue
		}
		for _, pod := range pods.Items {
			pi, err := PodInfo(pod, labelSelector)
			if err != nil {
				continue
			}
			components = append(components, *pi)
		}
	}
	return components, nil
}

func PodInfo(pod corev1.Pod, labelSelector string) (*bom.Component, error) {
	containers := make([]bom.Container, 0)
	for _, s := range pod.Status.ContainerStatuses {
		imageName, err := utils.ParseReference(s.Image)
		if err != nil {
			return nil, err
		}
		imageID := getImageID(s.ImageID, s.Image)
		if len(imageID) == 0 {
			continue
		}
		imageRef, err := utils.ParseReference(imageID)
		if err != nil {
			return nil, err
		}
		co, err := GetContainer(imageRef, imageName)
		if err != nil {
			continue
		}
		containers = append(containers, co)
	}
	props := make(map[string]string)
	componentValue, ok := pod.GetLabels()[labelSelector]
	if ok {
		props["Name"] = pod.Name
	}

	repoName := upstreamRepoByName(componentValue)
	if val, ok := CoreComponentPropertyType[repoName]; ok {
		props["Type"] = val
	}
	orgName := upstreamOrgByName(repoName)
	upstreamComponentName := repoName
	if len(orgName) > 0 {
		upstreamComponentName = fmt.Sprintf("%s/%s", orgName, repoName)
	}
	version := trimString(findComponentVersion(containers, componentValue), []string{"v", "V"})
	return &bom.Component{
		Namespace:  pod.Namespace,
		Name:       upstreamComponentName,
		Version:    version,
		Properties: props,
		Containers: containers,
	}, nil
}

func findComponentVersion(containers []bom.Container, name string) string {
	for _, c := range containers {
		if strings.Contains(c.ID, name) {
			return c.Version
		}
	}
	return ""
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
		ID:         "k8s.io/kubernetes",
		Type:       "Cluster",
		Version:    trimString(version, []string{"v", "V"}),
		Properties: map[string]string{"Name": name, "Type": "cluster"},
		NodesInfo:  nodeInfo,
	}
	return br, nil
}

func (c *cluster) ClusterNameVersion() (string, string, error) {
	rawCfg, err := c.cConfig.RawConfig()
	if err != nil {
		return "", "", err
	}
	clusterName := "k8s.io/kubernetes"
	if len(rawCfg.Contexts) > 0 {
		clusterName = rawCfg.Contexts[rawCfg.CurrentContext].Cluster
	}
	version, err := c.clientset.ServerVersion()
	if err != nil {
		return "", "", err
	}
	return clusterName, version.GitVersion, nil
}

// ListImagePullSecretsByPodSpec return image pull secrets by pod spec
func (r *cluster) ListImagePullSecretsByPodSpec(ctx context.Context, spec *corev1.PodSpec, ns string) (map[string]docker.Auth, error) {
	if spec == nil {
		return map[string]docker.Auth{}, nil
	}
	imagePullSecrets := spec.ImagePullSecrets

	sa, err := r.getServiceAccountByPodSpec(ctx, spec, ns)
	if err != nil && !k8sapierror.IsNotFound(err) && !k8sapierror.IsForbidden(err) {
		return nil, err
	}
	imagePullSecrets = append(sa.ImagePullSecrets, imagePullSecrets...)

	secrets, err := r.ListByLocalObjectReferences(ctx, imagePullSecrets, ns)
	if err != nil {
		return nil, err
	}

	return mapDockerRegistryServersToAuths(secrets, true)
}

func (r *cluster) getServiceAccountByPodSpec(ctx context.Context, spec *corev1.PodSpec, ns string) (*corev1.ServiceAccount, error) {
	serviceAccountName := spec.ServiceAccountName
	if serviceAccountName == "" {
		serviceAccountName = serviceAccountDefault
	}
	sa, err := r.clientset.CoreV1().ServiceAccounts(ns).Get(ctx, serviceAccountName, metav1.GetOptions{})
	if err != nil {
		return sa, fmt.Errorf("getting service account by name: %s/%s: %w", ns, serviceAccountName, err)
	}
	return sa, nil
}

func (r *cluster) ListByLocalObjectReferences(ctx context.Context, refs []corev1.LocalObjectReference, ns string) ([]*corev1.Secret, error) {
	secrets := make([]*corev1.Secret, 0)

	for _, secretRef := range refs {
		secret, err := r.clientset.CoreV1().Secrets(ns).Get(ctx, secretRef.Name, metav1.GetOptions{})
		if err != nil {
			if k8sapierror.IsNotFound(err) || k8sapierror.IsForbidden(err) {
				continue
			}
			return nil, fmt.Errorf("getting secret by name: %s/%s: %w", ns, secretRef.Name, err)
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

// MapDockerRegistryServersToAuths creates the mapping from a Docker registry server
// to the Docker authentication credentials for the specified slice of image pull Secrets.
func mapDockerRegistryServersToAuths(imagePullSecrets []*corev1.Secret, multiSecretSupport bool) (map[string]docker.Auth, error) {
	auths := make(map[string]docker.Auth)
	for _, secret := range imagePullSecrets {
		var data []byte
		var hasRequiredData, isLegacy bool

		switch secret.Type {
		case corev1.SecretTypeDockerConfigJson:
			data, hasRequiredData = secret.Data[corev1.DockerConfigJsonKey]
		case corev1.SecretTypeDockercfg:
			data, hasRequiredData = secret.Data[corev1.DockerConfigKey]
			isLegacy = true
		default:
			continue
		}

		// Skip a secrets of type "kubernetes.io/dockerconfigjson" or "kubernetes.io/dockercfg" which does not contain
		// the required ".dockerconfigjson" or ".dockercfg" key.
		if !hasRequiredData {
			continue
		}
		dockerConfig := &docker.Config{}
		err := dockerConfig.Read(data, isLegacy)
		if err != nil {
			return nil, fmt.Errorf("reading %s or %s field of %q secret: %w", corev1.DockerConfigJsonKey, corev1.DockerConfigKey, secret.Namespace+"/"+secret.Name, err)
		}
		for authKey, auth := range dockerConfig.Auths {
			server, err := docker.GetServerFromDockerAuthKey(authKey)
			if err != nil {
				return nil, err
			}
			if a, ok := auths[server]; multiSecretSupport && ok {
				user := fmt.Sprintf("%s,%s", a.Username, auth.Username)
				pass := fmt.Sprintf("%s,%s", a.Password, auth.Password)
				auths[server] = docker.Auth{Username: user, Password: pass}
			} else {
				auths[server] = auth
			}
		}
	}
	return auths, nil
}

type ContainerImages map[string]string

func MapContainerNamesToDockerAuths(imageRef string, auths map[string]docker.Auth) (*docker.Auth, error) {
	wildcardServers := GetWildcardServers(auths)

	var authsCred docker.Auth
	server, err := docker.GetServerFromImageRef(imageRef)
	if err != nil {
		return &authsCred, err
	}
	if auth, ok := auths[server]; ok {
		return &auth, nil
	}
	if len(wildcardServers) > 0 {
		if wildcardDomain := matchSubDomain(wildcardServers, server); len(wildcardDomain) > 0 {
			if auth, ok := auths[wildcardDomain]; ok {
				return &auth, nil
			}
		}
	}

	return nil, nil
}

func GetWildcardServers(auths map[string]docker.Auth) []string {
	wildcardServers := make([]string, 0)
	for server := range auths {
		if strings.HasPrefix(server, "*.") {
			wildcardServers = append(wildcardServers, server)
		}
	}
	return wildcardServers
}

func matchSubDomain(wildcardServers []string, subDomain string) string {
	for _, domain := range wildcardServers {
		domainWithoutWildcard := strings.Replace(domain, "*", "", 1)
		if strings.HasSuffix(subDomain, domainWithoutWildcard) {
			return domain
		}
	}
	return ""
}

func getWorkloadPodSpec(un unstructured.Unstructured) (*corev1.PodSpec, error) {
	switch un.GetKind() {
	case KindPod:
		objectMap, ok, err := unstructured.NestedMap(un.Object, []string{"spec"}...)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("unstructured resource do not match Pod spec")
		}
		return mapToPodSpec(objectMap)
	case KindCronJob:
		objectMap, ok, err := unstructured.NestedMap(un.Object, []string{"spec", "jobTemplate", "spec", "template", "spec"}...)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("unstructured resource do not match Pod spec")
		}
		return mapToPodSpec(objectMap)
	case KindDeployment, KindReplicaSet, KindReplicationController, KindStatefulSet, KindDaemonSet, KindJob:
		objectMap, ok, err := unstructured.NestedMap(un.Object, []string{"spec", "template", "spec"}...)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("unstructured resource do not match Pod spec")
		}
		return mapToPodSpec(objectMap)
	default:
		return nil, nil
	}
}

func mapToPodSpec(objectMap map[string]interface{}) (*corev1.PodSpec, error) {
	ps := &corev1.PodSpec{}
	err := ms.Decode(objectMap, ps)
	if err != nil && len(ps.Containers) == 0 {
		return nil, err
	}
	return ps, nil
}

func (r *cluster) AuthByResource(resource unstructured.Unstructured) (map[string]docker.Auth, error) {
	podSpec, err := getWorkloadPodSpec(resource)
	if err != nil {
		return nil, err
	}
	var serverAuths map[string]docker.Auth
	serverAuths, err = r.ListImagePullSecretsByPodSpec(context.Background(), podSpec, resource.GetNamespace())
	if err != nil {
		return nil, err
	}
	return serverAuths, nil
}

func upstreamOrgByName(component string) string {
	for key, components := range UpstreamOrgName {
		for _, c := range strings.Split(components, ",") {
			if strings.TrimSpace(c) == strings.ToLower(component) {
				return key
			}
		}
	}
	return ""
}

func upstreamRepoByName(component string) string {
	if val, ok := UpstreamRepoName[component]; ok {
		return val
	}
	return component
}

func trimString(version string, trimValues []string) string {
	for _, v := range trimValues {
		version = strings.Trim(version, v)
	}
	return strings.TrimSpace(version)
}

func getImageID(imageID string, image string) string {
	if len(imageID) > 0 {
		return imageID
	}
	imageParts := strings.Split(image, "@")
	if len(imageParts) > 1 && strings.HasPrefix(imageParts[1], "sha256") {
		return imageParts[1]
	}
	return ""
}
