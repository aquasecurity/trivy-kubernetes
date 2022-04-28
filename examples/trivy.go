package main

import (
	"fmt"
	"log"

	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"

	"context"
)

func main() {
	ctx := context.Background()

	fmt.Println("Scaning image on namespace 'default'")

	kubeConfig, err := trivyk8s.GetKubeConfig()
	if err != nil {
		log.Fatal(err)
	}

	trivyk8s, err := trivyk8s.New(kubeConfig)
	if err != nil {
		log.Fatal(err)
	}

	// empty means returns everything
	artifacts, err := trivyk8s.ListArtifacts(ctx, "")
	if err != nil {
		log.Fatal(err)
	}

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
