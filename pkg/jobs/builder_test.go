package jobs

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLoadBuilder(t *testing.T) {
	tests := []struct {
		name         string
		templateName string
		wantJob      *batchv1.Job
	}{
		{name: "node-collector job",
			templateName: "node-collector",
			wantJob: &batchv1.Job{
				TypeMeta: v1.TypeMeta{
					Kind:       "Job",
					APIVersion: "batch/v1",
				},
				ObjectMeta: v1.ObjectMeta{Name: "node-collector"},
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: v1.ObjectMeta{Labels: map[string]string{"app": "node-collector"}},
						Spec: corev1.PodSpec{
							HostPID: true,
							Containers: []corev1.Container{
								{
									Name:    "node-collector",
									Image:   "ghcr.io/aquasecurity/node-collector:0.0.5",
									Command: []string{"node-collector"},
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "var-lib-etcd",
											MountPath: "/var/lib/etcd",
											ReadOnly:  true,
										},
										{
											Name:      "var-lib-kubelet",
											MountPath: "/var/lib/kubelet",
											ReadOnly:  true,
										},
										{
											Name:      "var-lib-kube-scheduler",
											MountPath: "/var/lib/kube-scheduler",
											ReadOnly:  true,
										},
										{
											Name:      "var-lib-kube-controller-manager",
											MountPath: "/var/lib/kube-controller-manager",
											ReadOnly:  true,
										},
										{
											Name:      "etc-systemd",
											MountPath: "/etc/systemd",
											ReadOnly:  true,
										},
										{
											Name:      "lib-systemd",
											MountPath: "/lib/systemd/",
											ReadOnly:  true,
										},
										{
											Name:      "srv-kubernetes",
											MountPath: "/srv/kubernetes/",
											ReadOnly:  true,
										},
										{
											Name:      "etc-kubernetes",
											MountPath: "/etc/kubernetes",
											ReadOnly:  true,
										},
										{
											Name:      "usr-bin",
											MountPath: "/usr/local/mount-from-host/bin",
											ReadOnly:  true,
										},
										{
											Name:      "etc-cni-netd",
											MountPath: "/etc/cni/net.d/",
											ReadOnly:  true,
										},
										{
											Name:      "opt-cni-bin",
											MountPath: "/opt/cni/bin/",
											ReadOnly:  true,
										},
									},
								},
							},
							RestartPolicy: "Never",
							Volumes: []corev1.Volume{
								{
									Name:         "var-lib-etcd",
									VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/etcd"}},
								},
								{
									Name:         "var-lib-kubelet",
									VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kubelet"}},
								},
								{
									Name:         "var-lib-kube-scheduler",
									VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kube-scheduler"}},
								},
								{
									Name:         "var-lib-kube-controller-manager",
									VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kube-controller-manager"}},
								},
								{
									Name:         "etc-systemd",
									VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/systemd"}},
								},
								{
									Name:         "lib-systemd",
									VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/systemd"}},
								},
								{
									Name:         "srv-kubernetes",
									VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/srv/kubernetes"}},
								},
								{
									Name:         "etc-kubernetes",
									VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/kubernetes"}},
								},
								{
									Name:         "usr-bin",
									VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/bin"}},
								},
								{
									Name:         "etc-cni-netd",
									VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d/"}},
								},
								{
									Name:         "opt-cni-bin",
									VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin/"}},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotJob, err := GetJob(WithTemplate(tt.templateName))
			assert.NoError(t, err)
			assert.True(t, reflect.DeepEqual(gotJob, tt.wantJob))
		})
	}
}
