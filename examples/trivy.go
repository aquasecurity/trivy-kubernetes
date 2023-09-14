package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/pointer"
)

func newStdoutLogger() logr.Logger {
	return funcr.New(func(prefix, args string) {
		if prefix != "" {
			fmt.Printf("%s: %s\n", prefix, args)
		} else {
			fmt.Println(args)
		}
	}, funcr.Options{})
}

func main() {
	// create a new sink that will write to stdout
	// and use it to create a new logger
	logrusInterface := logrus.New()

	logr := newStdoutLogger()

	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	ctx := context.Background()

	cluster, err := k8s.GetCluster()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Current namespace:", cluster.GetCurrentNamespace())

	trivyk8sGoLogr := trivyk8s.New(cluster, logr, trivyk8s.WithExcludeOwned(true))
	trivyk8sLogrus := trivyk8s.New(cluster, logrusInterface, trivyk8s.WithExcludeOwned(true))
	trivyk8sZapSugar := trivyk8s.New(cluster, logger.Sugar(), trivyk8s.WithExcludeOwned(true))

	fmt.Println("Scanning cluster with zap logger")

	// trivy k8s #cluster
	artifacts, err := trivyk8sZapSugar.ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	// printArtifacts(artifacts)

	fmt.Println("Scanning cluster with logrus logger")
	artifacts, err = trivyk8sLogrus.ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	// printArtifacts(artifacts)

	fmt.Println("Scanning cluster with go-logr logger")
	artifacts, err = trivyk8sGoLogr.ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)

	fmt.Println("Scanning kind 'pods' with exclude-owned=true")
	artifacts, err = trivyk8sZapSugar.Resources("pod").AllNamespaces().ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)

	fmt.Println("Scanning namespace 'default'")
	// trivy k8s --namespace default
	artifacts, err = trivyk8sGoLogr.Namespace("default").ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)
	fmt.Println("Scanning all namespaces ")
	artifacts, err = trivyk8sGoLogr.AllNamespaces().ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)

	fmt.Println("Scanning namespace 'default', resource 'deployment/orion'")

	// trivy k8s --namespace default deployment/orion
	artifact, err := trivyk8sGoLogr.Namespace("default").GetArtifact(ctx, "deploy", "orion")
	if err != nil {
		log.Fatal(err)
	}
	printArtifact(artifact)

	fmt.Println("Scanning 'deployments'")

	// trivy k8s deployment
	artifacts, err = trivyk8sGoLogr.Namespace("default").Resources("deployment").ListArtifacts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	printArtifacts(artifacts)

	fmt.Println("Scanning 'cm,pods'")
	// trivy k8s clusterroles,pods
	artifacts, err = trivyk8sGoLogr.Namespace("default").Resources("cm,pods").ListArtifacts(ctx)
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
	ar, err := trivyk8sGoLogr.ListArtifactAndNodeInfo(ctx, "trivy-temp", map[string]string{"chen": "test"}, tolerations...)
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range ar {
		if a.Kind != "NodeInfo" {
			continue
		}
		fmt.Println(a.RawResource)
	}

	bi, err := trivyk8sZapSugar.ListBomInfo(ctx)
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
