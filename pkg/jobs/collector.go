package jobs

import (
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"gopkg.in/yaml.v3"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8sapierror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	NodeCollectorName = "node-collector"
	defaultNamespace  = "trivy-temp"

	// job headers
	TrivyCollectorName   = "trivy.collector.name"
	TrivyAutoCreated     = "trivy.automatic.created"
	TrivyResourceName    = "trivy.resource.name"
	TrivyResourceKind    = "trivy.resource.kind"
	commandsRootFolder   = "commands"
	k8sCommandFolder     = "kubernetes"
	configCommandsFolder = "config"

	k8sFsCommandPath    = "commands/kubernetes"
	configFsCommandPath = "commands/config"
)

type Collector interface {
	ApplyAndCollect(ctx context.Context, nodeName string) (string, error)
	Apply(ctx context.Context, nodeName string) (*batchv1.Job, error)
	AppendLabels(opts ...CollectorOption)
	Cleanup(ctx context.Context)
}

type jobCollector struct {
	cluster k8s.Cluster
	// timeout duration for collection job to complete it task before is cancelled default 0
	timeout              time.Duration
	logsReader           LogsReader
	labels               map[string]string
	annotation           map[string]string
	templateName         string
	namespace            string
	priorityClassName    string
	name                 string
	serviceAccount       string
	podSecurityContext   *corev1.PodSecurityContext
	securityContext      *corev1.SecurityContext
	imageRef             string
	affinity             *corev1.Affinity
	tolerations          []corev1.Toleration
	volumes              []corev1.Volume
	volumeMounts         []corev1.VolumeMount
	imagePullSecrets     []corev1.LocalObjectReference
	collectorTimeout     time.Duration
	resourceRequirements corev1.ResourceRequirements
	nodeConfig           bool
	useNodeSelector      bool
	commandPaths         []string
	specCommandIds       []string
	commandsFileSystem   embed.FS
	nodeConfigFileSystem embed.FS
}

type CollectorOption func(*jobCollector)

func WithTimetout(timeout time.Duration) CollectorOption {
	return func(jc *jobCollector) {
		jc.timeout = timeout
	}
}

func WithJobLabels(labels map[string]string) CollectorOption {
	return func(jc *jobCollector) {
		if jc.labels == nil {
			jc.labels = make(map[string]string)
		}
		for name, value := range labels {
			jc.labels[name] = value
		}
	}
}

func WithJobAnnotation(annotation map[string]string) CollectorOption {
	return func(jc *jobCollector) {
		jc.annotation = annotation
	}
}

func WithJobNamespace(namespace string) CollectorOption {
	return func(jc *jobCollector) {
		jc.namespace = namespace
	}
}

func WithPodPriorityClassName(priorityClassName string) CollectorOption {
	return func(jc *jobCollector) {
		jc.priorityClassName = priorityClassName
	}
}

func WithJobAffinity(affinity *corev1.Affinity) CollectorOption {
	return func(jc *jobCollector) {
		jc.affinity = affinity
	}
}

func WithJobTolerations(tolerations []corev1.Toleration) CollectorOption {
	return func(jc *jobCollector) {
		jc.tolerations = tolerations
	}
}

func WithName(name string) CollectorOption {
	return func(jc *jobCollector) {
		jc.name = name
	}
}

func WithNodeConfig(nodeConfig bool) CollectorOption {
	return func(jc *jobCollector) {
		jc.nodeConfig = nodeConfig
	}
}

func WithImageRef(imageRef string) CollectorOption {
	return func(jc *jobCollector) {
		jc.imageRef = imageRef
	}
}

func WithServiceAccount(sa string) CollectorOption {
	return func(jc *jobCollector) {
		jc.serviceAccount = sa
	}
}

func WithJobTemplateName(name string) CollectorOption {
	return func(jc *jobCollector) {
		jc.templateName = name
	}
}

func WithContainerResourceRequirements(rr corev1.ResourceRequirements) CollectorOption {
	return func(j *jobCollector) {
		j.resourceRequirements = rr
	}
}

func WithContainerSecurityContext(securityContext *corev1.SecurityContext) CollectorOption {
	return func(jc *jobCollector) {
		jc.securityContext = securityContext
	}
}

func WithPodSpecSecurityContext(podSecurityContext *corev1.PodSecurityContext) CollectorOption {
	return func(jc *jobCollector) {
		jc.podSecurityContext = podSecurityContext
	}
}

func WithVolumes(volumes []corev1.Volume) CollectorOption {
	return func(jc *jobCollector) {
		jc.volumes = volumes
	}
}
func WithVolumesMount(volumesMount []corev1.VolumeMount) CollectorOption {
	return func(jc *jobCollector) {
		jc.volumeMounts = volumesMount
	}
}

func WithPodImagePullSecrets(imagePullSecrets []corev1.LocalObjectReference) CollectorOption {
	return func(jc *jobCollector) {
		jc.imagePullSecrets = imagePullSecrets
	}
}

func WithCollectorTimeout(timeout time.Duration) CollectorOption {
	return func(jc *jobCollector) {
		jc.collectorTimeout = timeout
	}
}

func WithUseNodeSelector(useNodeSelector bool) CollectorOption {
	return func(jc *jobCollector) {
		jc.useNodeSelector = useNodeSelector
	}
}

func WithCommandsPath(commandPaths []string) CollectorOption {
	return func(jc *jobCollector) {
		jc.commandPaths = commandPaths
	}
}

func WithSpecCommands(specCommandIds []string) CollectorOption {
	return func(jc *jobCollector) {
		jc.specCommandIds = specCommandIds
	}
}

func WithEmbeddedCommandFileSystem(commandsFileSystem embed.FS) CollectorOption {
	return func(c *jobCollector) {
		c.commandsFileSystem = commandsFileSystem
	}
}

func WithEmbeddedNodeConfigFilesystem(nodeConfigFileSystem embed.FS) CollectorOption {
	return func(c *jobCollector) {
		c.nodeConfigFileSystem = nodeConfigFileSystem
	}
}

func NewCollector(
	cluster k8s.Cluster,
	opts ...CollectorOption,
) Collector {
	jc := &jobCollector{
		cluster:    cluster,
		timeout:    0,
		logsReader: NewLogsReader(cluster.GetK8sClientSet()),
	}
	for _, opt := range opts {
		opt(jc)
	}
	return jc
}

// AppendLabels Append labels to job
func (jb *jobCollector) AppendLabels(opts ...CollectorOption) {
	for _, opt := range opts {
		opt(jb)
	}
}

type ObjectRef struct {
	Kind      string
	Name      string
	Namespace string
}

// ApplyAndCollect deploy k8s job by template to  specific node  and namespace, it read pod logs
// cleaning up job and returning it output (for cli use-case)
func (jb *jobCollector) ApplyAndCollect(ctx context.Context, nodeName string) (string, error) {

	_, err := jb.getTrivyNamespace(ctx)
	if err != nil {
		if k8sapierror.IsNotFound(err) {
			trivyNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: jb.namespace}}
			_, err = jb.cluster.GetK8sClientSet().CoreV1().Namespaces().Create(ctx, trivyNamespace, metav1.CreateOptions{})
			if err != nil {
				return "", err
			}
		}
	}

	ca, err := jb.GetCollectorArgs()
	if err != nil {
		return "", err
	}
	JobOptions := []JobOption{
		WithTemplate(jb.templateName),
		WithNamespace(jb.namespace),
		WithNodeName(nodeName),
		WithAnnotation(jb.annotation),
		WithLabels(jb.labels),
		WithJobTimeout(jb.collectorTimeout),
		withSecurityContext(jb.securityContext),
		withPodSecurityContext(jb.podSecurityContext),
		WithNodeCollectorImageRef(jb.imageRef),
		WithAffinity(jb.affinity),
		WithTolerations(jb.tolerations),
		WithK8sNodeCommands(ca.commands),
		WithK8sKubeletConfigMapping(ca.kubeletConfigMapping),
		WithK8sNodeConfigData(ca.nodeConfigData),
		WithPodVolumes(jb.volumes),
		WithImagePullSecrets(jb.imagePullSecrets),
		WithContainerVolumeMounts(jb.volumeMounts),
		WithNodeConfiguration(true),
		WithPriorityClassName(jb.priorityClassName),
		WithResourceRequirements(jb.resourceRequirements),
		WithUseNodeSelectorParam(true),
		WithJobName(fmt.Sprintf("%s-%s", jb.templateName, ComputeHash(
			ObjectRef{
				Kind:      "Node-Info",
				Name:      nodeName,
				Namespace: jb.namespace,
			}))),
	}
	nc, err := jb.loadNodeConfig(ctx, nodeName)
	if err != nil {
		return "", fmt.Errorf("loading node config: %w", err)
	}
	JobOptions = append(JobOptions, WithKubeletConfig(nc))
	job, err := GetJob(JobOptions...)
	if err != nil {
		return "", fmt.Errorf("running node-collector job: %w", err)
	}

	err = New(WithTimeout(jb.timeout)).Run(ctx, NewRunnableJob(jb.cluster.GetK8sClientSet(), job))
	if err != nil {
		return "", fmt.Errorf("running node-collector job: %w", err)
	}
	defer func() {
		background := metav1.DeletePropagationBackground
		_ = jb.cluster.GetK8sClientSet().BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	logsStream, err := jb.logsReader.GetLogsByJobAndContainerName(ctx, job, NodeCollectorName)
	if err != nil {
		return "", fmt.Errorf("getting logs: %w", err)
	}
	defer func() {
		_ = logsStream.Close()
	}()
	output, err := io.ReadAll(logsStream)
	if err != nil {
		return "", fmt.Errorf("reading logs: %w", err)
	}
	return string(output), nil
}

func (jb jobCollector) loadNodeConfig(ctx context.Context, nodeName string) (string, error) {
	data, err := jb.cluster.GetK8sClientSet().RESTClient().Get().AbsPath(fmt.Sprintf("/api/v1/nodes/%s/proxy/configz", nodeName)).DoRaw(ctx)
	if err != nil {
		return "", err
	}
	return compressAndEncode(data)
}

type NodeCommands struct {
	Commands []any `yaml:"commands"`
}

func loadCommands(paths []string, AddCheckFunc AddChecks) (map[string][]any, map[string]string) {
	if len(paths) == 0 {
		return map[string][]any{}, map[string]string{}
	}
	configs := make(map[string]string)
	commands := make(map[string][]any)

	e := filepath.Walk(filepath.Join(paths[0], commandsRootFolder), func(path string, info os.FileInfo, err error) error {
		switch {
		case strings.Contains(path, filepath.Join(commandsRootFolder, k8sCommandFolder)) && filepath.Ext(path) == ".yaml":
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var cmd any
			err = yaml.Unmarshal(b, &cmd)
			if err != nil {
				return err
			}
			if commandArr, ok := cmd.([]interface{}); ok {
				if commandMap, ok := commandArr[0].(map[string]any); ok {
					AddCheckFunc(commands, commandMap)
				}
			}
		case strings.Contains(path, filepath.Join(commandsRootFolder, configCommandsFolder)) && filepath.Ext(path) == ".yaml":
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			nconfig, err := compressAndEncode(b)
			if err != nil {
				return err
			}
			configs[info.Name()] = nconfig
		}
		return nil
	})
	if e != nil {
		return map[string][]any{}, map[string]string{}
	}
	return commands, configs
}

func getEmbeddedCommands(commandsFileSystem embed.FS, nodeConfigFileSystem embed.FS, AddCheckFunc AddChecks) (map[string][]any, map[string]string) {
	commands := make(map[string][]any)
	configs := make(map[string]string)
	err := fs.WalkDir(commandsFileSystem, k8sFsCommandPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fContent, err := commandsFileSystem.ReadFile(path)
		if err != nil {
			return err
		}
		var cmd any
		err = yaml.Unmarshal(fContent, &cmd)
		if err != nil {
			return err
		}
		if commandArr, ok := cmd.([]interface{}); ok {
			if commandMap, ok := commandArr[0].(map[string]any); ok {
				AddCheckFunc(commands, commandMap)
			}
		}
		return nil
	})
	if err != nil {
		return map[string][]any{}, map[string]string{}
	}
	err = fs.WalkDir(nodeConfigFileSystem, configFsCommandPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		var fContent []byte
		fContent, err = nodeConfigFileSystem.ReadFile(path)
		if err != nil {
			return err
		}
		nconfig, err := compressAndEncode(fContent)
		if err != nil {
			return err
		}
		configs[d.Name()] = nconfig
		return nil
	})
	if err != nil {
		return map[string][]any{}, map[string]string{}
	}
	return commands, configs
}

type AddChecks func(addChecks map[string][]any, commandMap map[string]any)

func AddChecksByPlatform(addChecks map[string][]any, commandMap map[string]any) {
	if platform, ok := commandMap["platforms"]; ok {
		if platforms, ok := platform.([]interface{}); ok {
			for _, p := range platforms {
				pl := p.(string)
				if addChecks[pl] == nil {
					addChecks[pl] = make([]any, 0)
				}
				addChecks[pl] = append(addChecks[pl], commandMap)
			}
		}
	}
}

func AddChecksByCheckId(addChecks map[string][]any, commandMap map[string]any) {
	if id, ok := commandMap["id"]; ok {
		if idString, ok := id.(string); ok {
			if addChecks[idString] == nil {
				addChecks[idString] = make([]any, 0)
			}
			addChecks[idString] = append(addChecks[idString], commandMap)
		}
	}
}

func filterCommandBySpecId(commands map[string][]any, specCommandIds []string) NodeCommands {
	if len(specCommandIds) == 0 {
		return NodeCommands{}
	}
	filteredCommands := make([]any, 0)
	for _, id := range specCommandIds {
		if command, ok := commands[id]; ok {
			filteredCommands = append(filteredCommands, command...)
		}
	}
	return NodeCommands{Commands: filteredCommands}
}
func filterCommandByPlatform(commands map[string][]any, platform string) NodeCommands {
	filteredCommands := make([]any, 0)
	if command, ok := commands[platform]; ok {
		filteredCommands = append(filteredCommands, command...)
	}
	return NodeCommands{Commands: filteredCommands}
}

// Apply deploy k8s job by template to specific node and namespace (for operator use case)
func (jb *jobCollector) Apply(ctx context.Context, nodeName string) (*batchv1.Job, error) {
	ca, err := jb.GetCollectorArgs()
	if err != nil {
		return nil, err
	}
	jobOptions := []JobOption{
		WithNamespace(jb.namespace),
		WithLabels(jb.labels),
		withPodSecurityContext(jb.podSecurityContext),
		withSecurityContext(jb.securityContext),
		WithAffinity(jb.affinity),
		WithTolerations(jb.tolerations),
		WithJobServiceAccount(jb.serviceAccount),
		WithJobTimeout(jb.collectorTimeout),
		WithNodeCollectorImageRef(jb.imageRef),
		WithAnnotation(jb.annotation),
		WithTemplate(jb.templateName),
		WithK8sNodeCommands(ca.commands),
		WithK8sKubeletConfigMapping(ca.kubeletConfigMapping),
		WithK8sNodeConfigData(ca.nodeConfigData),
		WithPodVolumes(jb.volumes),
		WithNodeConfiguration(false),
		WithImagePullSecrets(jb.imagePullSecrets),
		WithContainerVolumeMounts(jb.volumeMounts),
		WithPriorityClassName(jb.priorityClassName),
		WithNodeName(nodeName),
		WithReplaceResourceReq(true),
		WithJobName(jb.name),
		WithUseNodeSelectorParam(jb.useNodeSelector),
		WithResourceRequirements(jb.resourceRequirements)}

	job, err := GetJob(jobOptions...)
	if err != nil {
		return nil, fmt.Errorf("running node-collector job: %w", err)
	}
	// create job
	job, err = jb.cluster.GetK8sClientSet().BatchV1().Jobs(job.Namespace).Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return job, nil
}

func (jb *jobCollector) deleteTrivyNamespace(ctx context.Context) {
	background := metav1.DeletePropagationBackground
	_ = jb.cluster.GetK8sClientSet().CoreV1().Namespaces().Delete(ctx, jb.namespace, metav1.DeleteOptions{
		PropagationPolicy: &background,
	})
}

func (jb *jobCollector) getTrivyNamespace(ctx context.Context) (*corev1.Namespace, error) {
	return jb.cluster.GetK8sClientSet().CoreV1().Namespaces().Get(ctx, jb.namespace, metav1.GetOptions{})
}

func (jb *jobCollector) Cleanup(ctx context.Context) {
	if jb.namespace != defaultNamespace {
		return
	}
	jb.deleteTrivyNamespace(ctx)
}

func (jb *jobCollector) GetCollectorArgs() (CollectorArgs, error) {
	var nodeCommands NodeCommands
	var configMap map[string]string
	var commandMap map[string][]any
	if len(jb.specCommandIds) > 0 {
		if len(jb.commandPaths) > 0 {
			commandMap, configMap = loadCommands(jb.commandPaths, AddChecksByCheckId)
		} else {
			commandMap, configMap = getEmbeddedCommands(jb.commandsFileSystem, jb.nodeConfigFileSystem, AddChecksByCheckId)
		}
		nodeCommands = filterCommandBySpecId(commandMap, jb.specCommandIds)
	} else {
		if len(jb.commandPaths) > 0 {
			commandMap, configMap = loadCommands(jb.commandPaths, AddChecksByPlatform)
		} else {
			commandMap, configMap = getEmbeddedCommands(jb.commandsFileSystem, jb.nodeConfigFileSystem, AddChecksByPlatform)
		}
		platform := jb.cluster.Platform()
		nodeCommands = filterCommandByPlatform(commandMap, platform.Name)
	}
	if len(nodeCommands.Commands) == 0 {
		return CollectorArgs{}, fmt.Errorf("no compliance commands found")
	}
	commands, err := yaml.Marshal(nodeCommands)
	if err != nil {
		return CollectorArgs{}, err
	}
	cdata, err := compressAndEncode(commands)
	if err != nil {
		return CollectorArgs{}, err
	}
	kubeletMapping, ok := configMap["kubelet_mapping.yaml"]
	if !ok {
		return CollectorArgs{}, fmt.Errorf("missing kubelet config mapping")
	}
	nodeCfg, ok := configMap["node.yaml"]
	if !ok {
		return CollectorArgs{}, fmt.Errorf("missing node config data")
	}

	return CollectorArgs{
		commands:             cdata,
		kubeletConfigMapping: kubeletMapping,
		nodeConfigData:       nodeCfg,
	}, nil
}

type CollectorArgs struct {
	commands             string
	kubeletConfigMapping string
	nodeConfigData       string
}
