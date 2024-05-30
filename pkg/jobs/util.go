package jobs

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"hash"
	"hash/fnv"

	"github.com/davecgh/go-spew/spew"
	"github.com/dsnet/compress/bzip2"

	"k8s.io/apimachinery/pkg/util/rand"
)

// ComputeHash returns a hash value calculated from a given object.
// The hash will be safe encoded to avoid bad words.
func ComputeHash(obj interface{}) string {
	podSpecHasher := fnv.New32a()
	deepHashObject(podSpecHasher, obj)
	return rand.SafeEncodeString(fmt.Sprint(podSpecHasher.Sum32()))
}

// deepHashObject writes specified object to hash using the spew library
// which follows pointers and prints actual values of the nested objects
// ensuring the hash does not change when a pointer changes.
func deepHashObject(hasher hash.Hash, objectToWrite interface{}) {
	hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", objectToWrite)
}

func compressAndEncode(data []byte) (string, error) {
	var buf bytes.Buffer
	w, err := bzip2.NewWriter(&buf, &bzip2.WriterConfig{Level: bzip2.DefaultCompression})
	if err != nil {
		return "", err
	}

	_, err = w.Write(data)
	if err != nil {
		return "", err
	}
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
