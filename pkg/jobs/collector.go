package jobs

import (
	"context"
	"fmt"
	"io"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ContainerName  = "node-collector"
	TrivyNamespace = "trivy-system"
)

type Collector interface {
	ApplyAndCollect(ctx context.Context, templateName string, nodeName string) (string, error)
	Apply(ctx context.Context, templateName string, nodeName string, namespace string) (*batchv1.Job, error)
}

type jobCollector struct {
	cluster    k8s.Cluster
	logsReader LogsReader
}

func NewCollector(
	cluster k8s.Cluster,
) Collector {
	return &jobCollector{
		cluster:    cluster,
		logsReader: NewLogsReader(cluster.GetK8sClientSet()),
	}
}

// ApplyAndCollect deploy k8s job by template to  specific node  and namespace, it read pod logs
// cleaning up job and returning it output (for cli use-case)
func (jb *jobCollector) ApplyAndCollect(ctx context.Context, templateName string, nodeName string) (string, error) {
	job, err := GetJob(WithTemplate(templateName), WithNodeSelector(nodeName), WithNamespace(TrivyNamespace))
	if err != nil {
		return "", fmt.Errorf("running node-collector job: %w", err)
	}
	// start with cleaning up namespace and jobs
	jb.deleteTrivyNamespace(ctx)
	trivyNamespace := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: TrivyNamespace}}
	_, err = jb.cluster.GetK8sClientSet().CoreV1().Namespaces().Create(ctx, trivyNamespace, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	defer func() {
		jb.deleteTrivyNamespace(ctx)
	}()

	err = New().Run(ctx, NewRunnableJob(jb.cluster.GetK8sClientSet(), job))
	if err != nil {
		return "", fmt.Errorf("running node-collector job: %w", err)
	}
	defer func() {
		background := metav1.DeletePropagationBackground
		_ = jb.cluster.GetK8sClientSet().BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	logsStream, err := jb.logsReader.GetLogsByJobAndContainerName(ctx, job, ContainerName)
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

// Apply deploy k8s job by template to specific node and namespace (for operator use case)
func (jb *jobCollector) Apply(ctx context.Context, templateName string, nodeName string, namespace string) (*batchv1.Job, error) {
	job, err := GetJob(WithTemplate(templateName), WithNodeSelector(nodeName), WithNamespace(namespace))
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
	_ = jb.cluster.GetK8sClientSet().CoreV1().Namespaces().Delete(ctx, TrivyNamespace, metav1.DeleteOptions{
		PropagationPolicy: &background,
	})
}
