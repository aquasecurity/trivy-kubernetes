package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/pointer"

	"context"
)

func main() {

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	ctx := context.Background()

	cluster, err := k8s.GetCluster()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Current namespace:", cluster.GetCurrentNamespace())

	trivyk8s := trivyk8s.New(cluster, logger.Sugar())

	fmt.Println("Scanning cluster")

	//trivy k8s #cluster
	artifacts, err := trivyk8s.ListArtifacts(ctx)
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
	ar, err := trivyk8s.ListArtifactAndNodeInfo(ctx, tolerations...)
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range ar {
		if a.Kind != "NodeInfo" {
			continue
		}
		fmt.Println(a.RawResource)
	}

	bi, err := trivyk8s.ListBomInfo(ctx)
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
