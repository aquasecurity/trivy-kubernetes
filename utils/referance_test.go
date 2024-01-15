package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseRef(t *testing.T) {
	t.Run("parses imgae ref with arn", func(t *testing.T) {
		imageRef, err := ParseReference("arn:aws:ecr:us-west-2:foo:repository/bar:latest")
		assert.NoError(t, err)
		assert.Equal(t, "repository/bar:latest", imageRef.String())
	})
	t.Run("parses imgae ref without arn", func(t *testing.T) {
		imageRef, err := ParseReference("k8s.gcr.io/etcd:3.4.13-0")
		assert.NoError(t, err)
		assert.Equal(t, "k8s.gcr.io/etcd:3.4.13-0", imageRef.String())
	})
}
