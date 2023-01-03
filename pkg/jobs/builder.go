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
}

func (b *JobBuilder) build() (*batchv1.Job, error) {
	var job batchv1.Job

	err := yaml.Unmarshal([]byte(b.template), &job)
	if err != nil {
		return nil, err
	}
	if len(b.namespace) > 0 {
		job.Namespace = b.namespace
	}
	if len(b.nodeSelector) > 0 {
		job.Spec.Template.Spec.NodeName = b.nodeSelector
	}
	return &job, nil
}
