package jobs

import (
	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/yaml"
)

type JobOption func(*JobBuilder)

func WithTemplate(template string) JobOption {
	return func(j *JobBuilder) {
		j.template = template
	}
}

func WithNodeSelector(nodeSelector string) JobOption {
	return func(j *JobBuilder) {
		j.nodeSelector = nodeSelector
	}
}
func WithNamespace(namespace string) JobOption {
	return func(j *JobBuilder) {
		j.namespace = namespace
	}
}

func WithLabels(labels map[string]string) JobOption {
	return func(j *JobBuilder) {
		j.labels = labels
	}
}

func GetJob(opts ...JobOption) (*batchv1.Job, error) {
	jb := &JobBuilder{}
	for _, opt := range opts {
		opt(jb)
	}
	return jb.build()
}

type JobBuilder struct {
	template     string
	nodeSelector string
	namespace    string
	labels       map[string]string
}

func (b *JobBuilder) build() (*batchv1.Job, error) {
	template := getTemplate(b.template)
	var job batchv1.Job

	err := yaml.Unmarshal([]byte(template), &job)
	if err != nil {
		return nil, err
	}
	job.Namespace = b.namespace

	if len(b.nodeSelector) > 0 {
		job.Spec.Template.Spec.NodeName = b.nodeSelector
	}
	job.Labels = b.labels
	return &job, nil
}
