package trivyk8s

import (
	"testing"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/stretchr/testify/assert"
)

func TestIgnoreNodeByLabel(t *testing.T) {
	tests := []struct {
		name          string
		ignoredLabels map[string]string
		artifact      *artifacts.Artifact
		want          bool
	}{
		{
			name:          "no ignore labels",
			ignoredLabels: map[string]string{},
			artifact:      &artifacts.Artifact{Labels: map[string]string{"a": "b"}},
			want:          false,
		},
		{
			name:          "matching ignore labels",
			ignoredLabels: map[string]string{"a": "b"},
			artifact:      &artifacts.Artifact{Labels: map[string]string{"a": "b"}},
			want:          true,
		},
		{
			name:          "non matching ignore labels",
			ignoredLabels: map[string]string{"a": "b", "c": "d"},
			artifact:      &artifacts.Artifact{Labels: map[string]string{"a": "b"}},
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ignoreNodeByLabel(tt.artifact, tt.ignoredLabels)
			assert.Equal(t, got, tt.want)
		})
	}
}
