package trivyk8s

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
)

func TestGetNamespaces(t *testing.T) {
	tests := []struct {
		name               string
		includeNamespaces  []string
		excludeNamespaces  []string
		mockNamespaces     []string
		mockError          error
		expectedNamespaces []string
		expectedError      error
	}{
		{
			name:               "No includeNamespaces, no excludeNamespaces",
			includeNamespaces:  nil,
			excludeNamespaces:  nil,
			mockNamespaces:     nil,
			expectedNamespaces: []string{},
			expectedError:      nil,
		},
		{
			name:               "Include namespaces set",
			includeNamespaces:  []string{"namespace1", "namespace2"},
			excludeNamespaces:  nil,
			mockNamespaces:     nil,
			expectedNamespaces: []string{"namespace1", "namespace2"},
			expectedError:      nil,
		},
		{
			name:               "Exclude namespaces set but no namespaces in cluster",
			includeNamespaces:  nil,
			excludeNamespaces:  []string{"namespace3"},
			mockNamespaces:     nil,
			expectedNamespaces: []string{},
			expectedError:      nil,
		},
		{
			name:               "Exclude namespaces set with namespaces in cluster",
			includeNamespaces:  nil,
			excludeNamespaces:  []string{"namespace3"},
			mockNamespaces:     []string{"namespace1", "namespace2", "namespace3"},
			expectedNamespaces: []string{"namespace1", "namespace2"},
			expectedError:      nil,
		},
		{
			name:               "Error in listing namespaces",
			includeNamespaces:  nil,
			excludeNamespaces:  []string{"namespace3"},
			mockError:          fmt.Errorf("some error"),
			expectedNamespaces: []string{},
			expectedError:      fmt.Errorf("unable to list namespaces: %v", fmt.Errorf("some error")),
		},
		{
			name:              "Forbidden error",
			includeNamespaces: nil,
			excludeNamespaces: []string{"namespace3"},
			mockError: errors.NewForbidden(schema.GroupResource{
				Group:    "",
				Resource: "namespaces",
			}, "namespaces", fmt.Errorf("forbidden")),
			expectedNamespaces: []string{},
			expectedError:      fmt.Errorf("'exclude namespaces' option requires a cluster role with permissions to list namespaces"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nsResource := k8s.NewMockNamespaceableResourceInterface(tt.mockNamespaces, tt.mockError)

			client := &client{
				includeNamespaces: tt.includeNamespaces,
				excludeNamespaces: tt.excludeNamespaces,
				cluster:           k8s.NewMockCluster(k8s.NewMockClusterDynamicClient(nsResource)),
			}

			// Run the test
			namespaces, err := client.getNamespaces()

			// Assert the expected values
			assert.ElementsMatch(t, namespaces, tt.expectedNamespaces)

			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

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
			name:         "scan only pods",
			includeKinds: []string{"pods"},
			excludeKinds: nil,
			want:         []string{k8s.Pods},
		},
		{
			name:         "skip ClusterRoles, Deployments and Ingresses",
			includeKinds: nil,
			excludeKinds: []string{"deployments", "ingresses", "clusterroles"},
			want: []string{
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
