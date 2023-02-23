package jobs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeHash(t *testing.T) {
	tests := []struct {
		name         string
		resourceName string
		want         string
	}{
		{name: "node-collector template", resourceName: "node-collector", want: "6c4db57695"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeHash(tt.resourceName)
			assert.Equal(t, tt.want, got)
		})
	}
}
