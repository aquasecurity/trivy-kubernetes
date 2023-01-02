package jobs

import (
	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/yaml"
)

func NewJobBuilder() *JobBuilder {
	return &JobBuilder{}
}

type JobBuilder struct {
	template     string
	nodeSelector string
	namespace    string
}

func (b *JobBuilder) JobTemplate(template string) *JobBuilder {
	b.template = template
	return b
}

func (b *JobBuilder) NodeSelector(nodeSelector string) *JobBuilder {
	b.nodeSelector = nodeSelector
	return b
}

func (b *JobBuilder) Get() (*batchv1.Job, error) {
	var job batchv1.Job

	err := yaml.Unmarshal([]byte(b.template), &job)
	if err != nil {
		return nil, err
	}
	return &job, nil
}
