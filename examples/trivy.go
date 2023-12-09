package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	tk "github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/pointer"

	"context"
)

func WithQPSBurst(qps float32, burst int) k8s.ClusterOption {
	return func(o *genericclioptions.ConfigFlags) {
		o.WrapConfigFn = func(c *rest.Config) *rest.Config {
			c.QPS = qps
			c.Burst = burst
			return c
		}
	}
}

func main() {

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	ctx := context.Background()

	cluster, err := k8s.GetCluster(WithQPSBurst(10000, 10000))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Current namespace:", cluster.GetCurrentNamespace())

	trivyk8s := tk.New(cluster, logger.Sugar(), tk.WithExcludeOwned(true))
	fmt.Println("Scanning cluster")

	//trivy k8s #cluster
	start := time.Now()
	artifacts, err := trivyk8s.ListArtifacts(ctx)
	end := time.Now()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Scan took %v\n", end.Sub(start))
	printArtifacts(artifacts)

	fmt.Println("Scanning kind 'pods' with exclude-owned=true")
	artifacts, err = trivyk8s.Resources("pod").AllNamespaces().ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)

	fmt.Println("Scanning namespace 'default'")
	//trivy k8s --namespace default
	artifacts, err = trivyk8s.Namespace("default").ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)
	fmt.Println("Scanning all namespaces ")
	artifacts, err = trivyk8s.AllNamespaces().ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)

	fmt.Println("Scanning namespace 'default', resource 'deployment/orion'")

	//trivy k8s --namespace default deployment/orion
	artifact, err := trivyk8s.Namespace("default").GetArtifact(ctx, "deploy", "orion")
	if err != nil {
		log.Fatal(err)
	}
	printArtifact(artifact)

	fmt.Println("Scanning 'deployments'")

	//trivy k8s deployment
	artifacts, err = trivyk8s.Namespace("default").Resources("deployment").ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)

	fmt.Println("Scanning 'cm,pods'")
	//trivy k8s clusterroles,pods
	artifacts, err = trivyk8s.Namespace("default").Resources("cm,pods").ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)

	tolerations := []corev1.Toleration{
		{
			Effect:   corev1.TaintEffectNoSchedule,
			Operator: corev1.TolerationOperator(corev1.NodeSelectorOpExists),
		},
		{
			Effect:   corev1.TaintEffectNoExecute,
			Operator: corev1.TolerationOperator(corev1.NodeSelectorOpExists),
		},
		{
			Effect:            corev1.TaintEffectNoExecute,
			Key:               "node.kubernetes.io/not-ready",
			Operator:          corev1.TolerationOperator(corev1.NodeSelectorOpExists),
			TolerationSeconds: pointer.Int64(300),
		},
		{
			Effect:            corev1.TaintEffectNoExecute,
			Key:               "node.kubernetes.io/unreachable",
			Operator:          corev1.TolerationOperator(corev1.NodeSelectorOpExists),
			TolerationSeconds: pointer.Int64(300),
		},
	}

	// collect node info
	ar, err := trivyk8s.ListArtifactAndNodeInfo(ctx, []tk.NodeCollectorOption{
		tk.WithScanJobNamespace("trivy-temp"),
		tk.WithIgnoreLabels(map[string]string{"chen": "test"}),
		tk.WithTolerations(tolerations)}...)
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range ar {
		if a.Kind != "NodeInfo" {
			continue
		}
		fmt.Println(a.RawResource)
	}

	bi, err := trivyk8s.ListClusterBomInfo(ctx)
	if err != nil {
		log.Fatal(err)
	}
	bb, err := json.Marshal(bi)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(bb))
}

func printArtifacts(artifacts []*artifacts.Artifact) {
	for _, artifact := range artifacts {
		printArtifact(artifact)
	}
}

func printArtifact(artifact *artifacts.Artifact) {
	fmt.Printf(
		"Name: %s, Kind: %s, Namespace: %s, Images: %v\n",
		artifact.Name,
		artifact.Kind,
		artifact.Namespace,
		artifact.Images,
	)
}
