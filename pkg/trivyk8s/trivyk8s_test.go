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

func TestFilterResource(t *testing.T) {
	tests := []struct {
		name         string
		resourceKind string
		excludeKinds []string
		includeKinds []string
		want         bool
	}{
		{
			name:         "filterKinds with excludeKinds",
			resourceKind: "Pod",
			excludeKinds: []string{"pod"},
			includeKinds: []string{},
			want:         true,
		},
		{
			name:         "filterKinds with includeKinds",
			resourceKind: "Pod",
			includeKinds: []string{"deployment"},
			excludeKinds: []string{},
			want:         true,
		},
		{
			name:         "filterKinds with excludeKinds and includeKinds",
			resourceKind: "Pod",
			includeKinds: []string{"pod"},
			excludeKinds: []string{"pod"},
			want:         false,
		},
		{
			name:         "filterKinds with no excludeKinds and no includeKinds",
			resourceKind: "Pod",
			includeKinds: []string{},
			excludeKinds: []string{},
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterResources(tt.includeKinds, tt.excludeKinds, tt.resourceKind)
			assert.Equal(t, got, tt.want)
		})
	}
}
