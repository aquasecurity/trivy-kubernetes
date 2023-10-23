package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseRef(t *testing.T) {
	imageRef, err := ParseReference("arn:aws:ecr:us-west-2:foo:repository/bar:latest")
	assert.NoError(t, err)
	assert.Equal(t, "repository/bar:latest", imageRef.String())
}
