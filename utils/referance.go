package utils

import (
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	containerimage "github.com/google/go-containerregistry/pkg/name"
)

func ParseReference(ref string) (containerimage.Reference, error) {
	if strings.HasPrefix(ref, "arn:aws:ecr") {
		parsed, err := arn.Parse(ref)
		if err != nil {
			return nil, err
		}
		ref = parsed.Resource
	}
	return containerimage.ParseReference(ref)
}
