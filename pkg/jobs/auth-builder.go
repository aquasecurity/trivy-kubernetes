package jobs

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

const (
	clusterRole    = "node-collector-cr"
	roleBinding    = "node-collector-rb"
	serviceAccount = "node-collector-sa"
)

type AuthOption func(*AuthBuilder)

func WithServiceAccountNamespace(namespace string) AuthOption {
	return func(a *AuthBuilder) {
		a.namespace = namespace
	}
}

func GetAuth(opts ...AuthOption) (*rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding, *corev1.ServiceAccount, error) {
	ab := &AuthBuilder{}
	for _, opt := range opts {
		opt(ab)
	}
	return ab.build()
}

type AuthBuilder struct {
	namespace string
}

func (b *AuthBuilder) build() (*rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding, *corev1.ServiceAccount, error) {
	// load ClusterRole, ClusterRoleBinding, ServiceAccount
	template := getTemplate(clusterRole)
	var cr rbacv1.ClusterRole
	err := yaml.Unmarshal([]byte(template), &cr)
	if err != nil {
		return nil, nil, nil, err
	}
	template = getTemplate(roleBinding)
	var rb rbacv1.ClusterRoleBinding
	err = yaml.Unmarshal([]byte(template), &rb)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(b.namespace) > 0 {
		rb.Subjects[0].Namespace = b.namespace
	}
	template = getTemplate(serviceAccount)
	var sa corev1.ServiceAccount
	err = yaml.Unmarshal([]byte(template), &sa)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(b.namespace) > 0 {
		sa.Namespace = b.namespace
	}
	return &cr, &rb, &sa, nil

}
