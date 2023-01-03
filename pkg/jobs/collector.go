package jobs

import (
	"context"
	"fmt"
	"io"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	containerName = "node-collector"
)

type Collector interface {
	ApplyAndCollect(ctx context.Context, templateName string, nodeName string, namespace string) (string, error)
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

// ApplyAndCollect apply job , take care of cleanup and collect it output
func (jb *jobCollector) ApplyAndCollect(ctx context.Context, templateName string, nodeName string, namespace string) (string, error) {
	job, err := GetJob(WithTemplate(templateName), WithNodeSelector(nodeName), WithNamespace(namespace))
	if err != nil {
		return "", fmt.Errorf("running kube-bench job: %w", err)
	}
	err = New().Run(ctx, NewRunnableJob(jb.cluster.GetK8sClientSet(), job))
	if err != nil {
		return "", fmt.Errorf("running kube-bench job: %w", err)
	}
	if err != nil {
		return "", fmt.Errorf("running kube-bench job: %w", err)
	}
	defer func() {
		background := metav1.DeletePropagationBackground
		_ = jb.cluster.GetK8sClientSet().BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	logsStream, err := jb.logsReader.GetLogsByJobAndContainerName(ctx, job, containerName)
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

// ApplyAndCollect apply job only
func (jb *jobCollector) Apply(ctx context.Context, templateName string, nodeName string, namespace string) (*batchv1.Job, error) {
	job, err := GetJob(WithTemplate(templateName), WithNodeSelector(nodeName), WithNamespace(namespace))
	if err != nil {
		return job, err
	}
	job, err = jb.cluster.GetK8sClientSet().BatchV1().Jobs(job.Namespace).Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		return job, err
	}
	return job, nil
}
