package jobs

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadSpecs(t *testing.T) {
	tests := []struct {
		name         string
		specName     string
		wantSpecPath string
	}{
		{name: "node-collector template", specName: "node-collector", wantSpecPath: "./template/node-collector.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantSpecPath != "" {
				wantSpecData, err := os.ReadFile(tt.wantSpecPath)
				assert.NoError(t, err)
				gotSpecData := GetTemplate(tt.specName)
				assert.Equal(t, gotSpecData, string(wantSpecData))
			} else {
				assert.Empty(t, GetTemplate(tt.specName), tt.name)
			}
		})
	}
}