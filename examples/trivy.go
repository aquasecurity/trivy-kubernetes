package main

import (
	"fmt"
	"log"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"go.uber.org/zap"

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

	// collect node info
	ar, err := trivyk8s.ListArtifactAndNodeInfo(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range ar {
		if a.Kind != "NodeInfo" {
			continue
		}
		fmt.Println(a.RawResource)
	}
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
