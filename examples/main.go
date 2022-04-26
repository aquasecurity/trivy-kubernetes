package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/aquasecurity/trivy-kubernetes/pkg/images"
	"github.com/olekukonko/tablewriter"

	"context"
)

func main() {
	ctx := context.Background()

	fmt.Println("Scaning image on namespace 'default'")

	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	kubeConfigPath := filepath.Join(userHomeDir, ".kube", "config")
	fmt.Printf("Using kubeconfig: %s\n", kubeConfigPath)

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		log.Fatal(err)
	}

	dynamicClient, err := dynamic.NewForConfig(kubeConfig)
	if err != nil {
		log.Fatal(err)
	}

	imagesClient := images.New(dynamicClient)
	images, err := imagesClient.ListAllByNamespace(ctx, "default")
	if err != nil {
		log.Fatal(err)
	}

	data := make([][]string, 0, len(images))

	for _, image := range images {
		d := make([]string, 3)
		d[0] = fmt.Sprintf("%s/%s", image.Resource, image.Name)
		d[1] = image.Image

		file, err := ioutil.TempFile("/tmp", "trivy")
		if err != nil {
			log.Fatal(err)
		}
		defer os.Remove(file.Name())

		cmd := exec.Command("trivy", "image", "--output", file.Name(), "--format", "json", image.Image)
		err = cmd.Run()
		if err != nil {
			d[2] = "error scanning image"
			data = append(data, d)
			continue
		}

		d[2] = parseVulnerabitilies(file.Name())
		data = append(data, d)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.AppendBulk(data)
	table.SetHeader([]string{
		"Resource",
		"Image",
		"Vunerabilities",
	})

	table.SetRowLine(true)
	table.Render() // Send output
}

func parseVulnerabitilies(fileName string) string {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}

	var m map[string]interface{}
	err = json.Unmarshal([]byte(file), &m)
	if err != nil {
		log.Fatal(err)
	}

	low := 0
	medium := 0
	high := 0
	critical := 0

	if results, ok := m["Results"].([]interface{}); ok {
		for _, result := range results {
			r := result.(map[string]interface{})
			if vulns, ok := r["Vulnerabilities"].([]interface{}); ok {
				for _, vuln := range vulns {
					v := vuln.(map[string]interface{})
					switch v["Severity"].(string) {
					case "CRITICAL":
						critical++
					case "HIGH":
						high++
					case "MEDIUM":
						medium++
					case "LOW":
						low++
					}
				}
			}
		}
	}

	return fmt.Sprintf("Low: %d, Medium: %d, High: %d, Critical: %d", low, medium, high, critical)
}
