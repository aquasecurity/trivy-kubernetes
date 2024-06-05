package e2e

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	tk "github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
)

func TestNodeInfo(T *testing.T) {
	ctx := context.Background()
	if testing.Short() {
		T.Skip("skipping end-to-end test")
	}
	cluster, err := k8s.GetCluster(k8s.WithBurst(100))
	if err != nil {
		panic(err)
	}
	trivyk8s := tk.New(cluster, tk.WithExcludeOwned(true))
	// collect node info
	ar, err := trivyk8s.ListArtifactAndNodeInfo(ctx, []tk.NodeCollectorOption{
		tk.WithScanJobNamespace("trivy-temp"),
		tk.WithCommandPaths([]string{"./testdata"}),
		tk.WithScanJobImageRef("ghcr.io/aquasecurity/node-collector:0.3.0"),
	}...)
	assert.NoError(T, err)
	for _, a := range ar {
		if a.Kind != "NodeInfo" {
			continue
		}
		var expectedNodeIbfo map[string]interface{}
		b, err := os.ReadFile("./testdata/expected_node_info.json")
		assert.NoError(T, err)
		err = json.Unmarshal(b, &expectedNodeIbfo)
		assert.NoError(T, err)
		assert.True(T, reflect.DeepEqual(expectedNodeIbfo["info"], a.RawResource["info"]))
	}
}

func TestKBOM(T *testing.T) {
	ctx := context.Background()
	if testing.Short() {
		T.Skip("skipping end-to-end test")
	}
	cluster, err := k8s.GetCluster(k8s.WithBurst(100))
	if err != nil {
		panic(err)
	}
	trivyk8s := tk.New(cluster, tk.WithExcludeOwned(true))
	// collect bom info
	gotBom, err := trivyk8s.ListClusterBomInfo(ctx)
	assert.NoError(T, err)
	want, err := os.ReadFile("./testdata/expected_bom.json")
	assert.NoError(T, err)
	var wantBom []*artifacts.Artifact
	err = json.Unmarshal(want, &wantBom)
	assert.NoError(T, err)
	// handle changes values
	for _, bm := range gotBom {
		if a, ok := bm.RawResource["Properties"]; ok {
			if prop, ok := a.(map[string]interface{}); ok {
				prop["Name"] = "ignore value"
				if _, ok := prop["KernelVersion"]; ok {
					prop["KernelVersion"] = "no version"
				}
			}
		}
		if _, ok := bm.RawResource["OsImage"]; ok {
			bm.RawResource["OsImage"] = "ignore value"
		}
	}
	assert.True(T, reflect.DeepEqual(wantBom, gotBom))
}
