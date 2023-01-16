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
func WithJobName(name string) JobOption {
	return func(j *JobBuilder) {
		j.name = name
	}
}
func WithNamespace(namespace string) JobOption {
	return func(j *JobBuilder) {
		j.namespace = namespace
	}
}

func WithJobServiceAccount(sa string) JobOption {
	return func(j *JobBuilder) {
		j.serviceAccount = sa
	}
}

func WithLabels(labels map[string]string) JobOption {
	return func(j *JobBuilder) {
		j.labels = labels
	}
}

func WithAnnotation(annotations map[string]string) JobOption {
	return func(j *JobBuilder) {
		j.annotations = annotations
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
	template       string
	nodeSelector   string
	namespace      string
	serviceAccount string
	name           string
	labels         map[string]string
	annotations    map[string]string
}

func (b *JobBuilder) build() (*batchv1.Job, error) {
	template := getTemplate(b.template)
	var job batchv1.Job

	err := yaml.Unmarshal([]byte(template), &job)
	if err != nil {
		return nil, err
	}
	job.Namespace = b.namespace
	if len(b.name) > 0 {
		job.Name = b.name
	}

	if len(b.nodeSelector) > 0 {
		job.Spec.Template.Spec.NodeName = b.nodeSelector
	}
	// append lables
	for key, val := range b.labels {
		if job.Labels == nil {
			job.Labels = make(map[string]string)
		}
		job.Labels[key] = val
	}
	// append annotation
	for key, val := range b.annotations {
		if job.Annotations == nil {
			job.Annotations = make(map[string]string)
		}
		job.Annotations[key] = val
	}
	if len(b.serviceAccount) > 0 {
		job.Spec.Template.Spec.ServiceAccountName = b.serviceAccount
	}

	return &job, nil
}
