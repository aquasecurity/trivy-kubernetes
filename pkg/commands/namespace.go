package commands

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-kubernetes/pkg/flag"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/aquasecurity/trivy/pkg/log"
)

// namespaceRun runs scan on kubernetes cluster
func namespaceRun(ctx context.Context, opts flag.Options, cluster k8s.Cluster) error {
	if err := validateReportArguments(opts); err != nil {
		return err
	}
	var trivyk trivyk8s.TrivyK8S
	if opts.AllNamespaces {
		trivyk = trivyk8s.New(cluster, log.Logger).AllNamespaces()
	} else {
		trivyk = trivyk8s.New(cluster, log.Logger).Namespace(getNamespace(opts, cluster.GetCurrentNamespace()))
	}

	artifacts, err := trivyk.ListArtifacts(ctx)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	runner := newRunner(opts, cluster.GetCurrentContext())
	return runner.run(ctx, artifacts)
}

func getNamespace(opts flag.Options, currentNamespace string) string {
	if len(opts.K8sOptions.Namespace) > 0 {
		return opts.K8sOptions.Namespace
	}

	return currentNamespace
}
