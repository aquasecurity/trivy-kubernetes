package trivyk8s

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
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
			got := FilterResources(tt.includeKinds, tt.excludeKinds, tt.resourceKind)
			assert.Equal(t, got, tt.want)
		})
	}
}

func TestInitResources(t *testing.T) {
	tests := []struct {
		name         string
		includeKinds []string
		excludeKinds []string
		want         []string
	}{
		{
			"scan only pods",
			[]string{"pods"},
			nil,
			[]string{k8s.Pods},
		},
		{
			"skip ClusterRoles, Deployments and Ingresses",
			nil,
			[]string{"deployments", "ingresses", "clusterroles"},
			[]string{
				k8s.ClusterRoleBindings,
				k8s.Nodes,
				k8s.Pods,
				k8s.ReplicaSets,
				k8s.ReplicationControllers,
				k8s.StatefulSets,
				k8s.DaemonSets,
				k8s.CronJobs,
				k8s.Jobs,
				k8s.Services,
				k8s.ServiceAccounts,
				k8s.ConfigMaps,
				k8s.Roles,
				k8s.RoleBindings,
				k8s.NetworkPolicies,
				k8s.ResourceQuotas,
				k8s.LimitRanges,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &client{excludeKinds: tt.excludeKinds, includeKinds: tt.includeKinds}
			c.initResourceList()
			assert.Equal(t, tt.want, c.resources)
		})
	}
}
