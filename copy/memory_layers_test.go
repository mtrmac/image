package copy

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/pkg/compression"
	compressiontypes "github.com/containers/image/v5/pkg/compression/types"
	digest "github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// uncompressedTestLayer creates a fake layer that depends on the submitted index.
func uncompressedTestLayer(index int) []byte {
	// For simplicity we create "layers" that are not valid tar files.
	// The generic copy code does not care, and this will be useful for eventual support of OCI artifacts anyway.
	return []byte(fmt.Sprintf("Test layer %d", index))
}

// compressedBytes returns input data compressed with the specified algorithm.
func compressedBytes(t *testing.T, data []byte, algo compressiontypes.Algorithm) []byte {
	buf := &bytes.Buffer{}
	compressor, err := compression.CompressStream(buf, algo, nil)
	require.NoError(t, err)
	n, err := compressor.Write(data)
	require.NoError(t, err)
	require.Equal(t, len(data), int64(n))
	err = compressor.Close()
	require.NoError(t, err)
	res, err := io.ReadAll(buf)
	require.NoError(t, err)
	return res
}

// decompressedBytes returns input data compressed with the specified algorithm.
func decompressedBytes(t *testing.T, data []byte, algo compressiontypes.Algorithm) []byte {
	buf := &bytes.Buffer{}
	compressor, err := compression.CompressStream(buf, algo, nil)
	require.NoError(t, err)
	n, err := compressor.Write(data)
	require.NoError(t, err)
	require.Equal(t, len(data), int64(n))
	err = compressor.Close()
	require.NoError(t, err)
	res, err := io.ReadAll(buf)
	require.NoError(t, err)
	return res
}

// addLayers adds a set of layers with the provided MIME types, in order, which can be later verified with memoryImageDigest.checkLayers, and returns the corresponding digests
func (mis *memoryImageSource) addLayers(t *testing.T, mimeTypes []string) []digest.Digest {
	res := []digest.Digest{}
	for layerIndex, mimeType := range mimeTypes {
		// For simplicity we create "layers" that are not valid tar files
		data := uncompressedTestLayer(layerIndex)
		switch mimeType {
		case manifest.DockerV2SchemaLayerMediaTypeUncompressed, imgspecv1.MediaTypeImageLayer:
			// Nothing
		case manifest.DockerV2Schema2ForeignLayerMediaTypeGzip, imgspecv1.MediaTypeImageLayerGzip:
			data = compressedBytes(t, data, compression.Gzip)
		case imgspecv1.MediaTypeImageLayerZstd:
			data = compressedBytes(t, data, compression.Zstd)
		}
		digest := mis.addBlob(data)
		res = append(res, digest)
	}
	return res
}

// verifyLayers verifies that layers created using addLayers exist with the provided digests, and match (possibly different) provided MIME types
func (mid *memoryImageDestination) verifyLayers(t *testing.T, digests []digest.Digest, mimeTypes []string) {
	require.Len(t, digests, len(mimeTypes))
	for layerIndex, mimeType := range mimeTypes {
		layerName := fmt.Sprintf("layer %d digest %s", layerIndex, digests[layerIndex])
		data, ok := mid.blobs[digests[layerIndex]]
		require.True(t, ok, layerName)
		switch mimeType {
		case manifest.DockerV2SchemaLayerMediaTypeUncompressed, imgspecv1.MediaTypeImageLayer:
			// Nothing
		case manifest.DockerV2Schema2ForeignLayerMediaTypeGzip, imgspecv1.MediaTypeImageLayerGzip:
			data = decompressedBytes(t, data, compression.Gzip)
		case imgspecv1.MediaTypeImageLayerZstd:
			data = decompressedBytes(t, data, compression.Zstd)
		}
		assert.Equal(t, uncompressedTestLayer(layerIndex), data, layerName)
	}
}
