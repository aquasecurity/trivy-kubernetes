package main

import (
	"fmt"
	"log"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"

	"context"
)

func main() {
	ctx := context.Background()

	fmt.Println("Scaning image cluster")

	kubeConfig, err := k8s.GetKubeConfig()
	if err != nil {
		log.Fatal(err)
	}

	k8sClient, err := k8s.NewDynamicClient(kubeConfig)
	if err != nil {
		log.Fatal(err)
	}

	trivyk8s := trivyk8s.New(k8sClient)

	//trivy k8s #cluster
	artifacts, err := trivyk8s.ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)

	//trivy k8s --namespace default
	artifacts, err = trivyk8s.Namespace("default").ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)
}

func printArtifacts(artifacts []*artifacts.Artifact) {
	for _, artifact := range artifacts {
		fmt.Printf(
			"Name: %s, Kind: %s, Namespace: %s, Images: %v\n",
			artifact.Name,
			artifact.Kind,
			artifact.Namespace,
			artifact.Images,
		)
	}

}
