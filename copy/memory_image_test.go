package copy

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/internal/testing/mocks"
	"github.com/containers/image/v5/types"
	digest "github.com/opencontainers/go-digest"
)

// memoryImageTransport contains memoryImageReference values
var memoryImageTransport = mocks.NameImageTransport("==copy.Image transport mock")

// memoryImageReference is a way to provide a memoryImageSource or memoryImageDestination to tested copy.Image
type memoryImageReference struct {
	name string
	src  types.ImageSource
	dest types.ImageDestination
}

func (mir *memoryImageReference) Transport() types.ImageTransport {
	return memoryImageTransport
}

func (mir *memoryImageReference) StringWithinTransport() string {
	return "==memoryImageReference " + mir.name
}

func (mir *memoryImageReference) DockerReference() reference.Named {
	return nil
}

func (mir *memoryImageReference) PolicyConfigurationIdentity() string {
	return "==memoryImageReference identity " + mir.name
}

func (mir *memoryImageReference) PolicyConfigurationNamespaces() []string {
	return nil
}

func (mir *memoryImageReference) NewImage(ctx context.Context, sys *types.SystemContext) (types.ImageCloser, error) {
	panic("Unexpected call to a mock function") // We expect copy.Image to construct this from NewImageSource only after checking signatures
}

func (mir *memoryImageReference) NewImageSource(ctx context.Context, sys *types.SystemContext) (types.ImageSource, error) {
	return mir.src, nil
}

func (mir *memoryImageReference) NewImageDestination(ctx context.Context, sys *types.SystemContext) (types.ImageDestination, error) {
	return mir.dest, nil
}

func (mir *memoryImageReference) DeleteImage(ctx context.Context, sys *types.SystemContext) error {
	panic("Unexpected call to a mock function")
}

// memoryInstanceKey turns an optional instanceDigest into a string, either a digest.Digest.String(), or "" for the default instance
func memoryInstanceKey(instanceDigest *digest.Digest) string {
	if instanceDigest != nil {
		return instanceDigest.String()
	}
	return ""
}

// memoryImageSource is an in-memory image source we use for testing copy.Image
type memoryImageSource struct {
	ref        types.ImageReference
	manifests  map[string][]byte // The key is from memoryInstanceKey
	blobs      map[digest.Digest][]byte
	signatures map[string][][]byte
}

// newMemoryImageSource returns an empty memoryImageSource that can be filled in using set...
// Use the .ref field to get a types.ImageReference to it.
func newMemoryImageSource(name string) *memoryImageSource {
	ref := &memoryImageReference{
		name: name,
	}
	src := &memoryImageSource{
		ref: ref,
	}
	ref.src = src
	return src
}

// addBlob adds a blob with data to the source, and returns a digest that can be used to reference it.
// see also addLayers
func (mis *memoryImageSource) addBlob(data []byte) digest.Digest {
	digest := digest.FromBytes(data)
	mis.blobs[digest] = data
	return digest
}

// addManifest adds a manifest to the source
func (mis *memoryImageSource) addManifest(data []byte, instanceDigest *digest.Digest) {
	mis.manifests[memoryInstanceKey(instanceDigest)] = data
}

// addSignatures adds signatures to the source
func (mis *memoryImageSource) addSignatures(data [][]byte, instanceDigest *digest.Digest) {
	mis.signatures[memoryInstanceKey(instanceDigest)] = data
}

func (mis *memoryImageSource) Reference() types.ImageReference {
	return mis.ref
}

func (mis *memoryImageSource) Close() error {
	return nil
}

func (mis *memoryImageSource) GetManifest(ctx context.Context, instanceDigest *digest.Digest) ([]byte, string, error) {
	key := memoryInstanceKey(instanceDigest)
	res, ok := mis.manifests[key]
	if !ok {
		return nil, "", fmt.Errorf("Manifest %q not found", key)
	}
	return res, "", nil
}

func (mis *memoryImageSource) GetBlob(ctx context.Context, blobInfo types.BlobInfo, bic types.BlobInfoCache) (io.ReadCloser, int64, error) {
	res, ok := mis.blobs[blobInfo.Digest]
	if !ok {
		return nil, -1, fmt.Errorf("Blob %q not found", blobInfo.Digest)
	}
	return io.NopCloser(bytes.NewReader(res)), int64(len(res)), nil
}

func (mis *memoryImageSource) HasThreadSafeGetBlob() bool {
	return true
}

func (mis *memoryImageSource) GetSignatures(ctx context.Context, instanceDigest *digest.Digest) ([][]byte, error) {
	key := memoryInstanceKey(instanceDigest)
	res, ok := mis.signatures[key]
	if !ok {
		if _, ok := mis.manifests[key]; !ok {
			return nil, fmt.Errorf("Manifest %q not found", key) // This should never happen
		}
		return nil, nil // Allow creating a memoryImageSource without defining signatures explicitly
	}
	return res, nil
}

func (mis *memoryImageSource) LayerInfosForCopy(ctx context.Context, instanceDigest *digest.Digest) ([]types.BlobInfo, error) {
	return nil, nil
}

// memoryImageDestination is an in-memory image destination we use for testing copy.Image
type memoryImageDestination struct {
	ref types.ImageReference
	// The following properties can be manually set by the caller before the memoryImageDestination is used.
	supportedManifestMIMETypes []string
	desiredLayerCompression    types.LayerCompression

	manifests  map[string][]byte // The key is from memoryInstanceKey
	blobs      map[digest.Digest][]byte
	signatures map[string][][]byte
}

// newMemoryImageDestinationreturns an empty memoryImageDestination.
// Use the .ref field to get a types.ImageReference to it.
func newMemoryImageDestination(name string) *memoryImageDestination {
	ref := &memoryImageReference{
		name: name,
	}
	dest := &memoryImageDestination{
		ref:                        ref,
		supportedManifestMIMETypes: nil,
		desiredLayerCompression:    types.PreserveOriginal,
	}
	ref.dest = dest
	return dest
}

func (mid *memoryImageDestination) Reference() types.ImageReference {
	return mid.ref
}

func (mid *memoryImageDestination) Close() error {
	return nil
}

func (mid *memoryImageDestination) SupportedManifestMIMETypes() []string {
	return mid.supportedManifestMIMETypes
}

func (mid *memoryImageDestination) SupportsSignatures(ctx context.Context) error {
	return nil
}

func (mid *memoryImageDestination) DesiredLayerCompression() types.LayerCompression {
	return mid.desiredLayerCompression
}

func (mid *memoryImageDestination) AcceptsForeignLayerURLs() bool {
	return true
}

func (mid *memoryImageDestination) MustMatchRuntimeOS() bool {
	return false
}

func (mid *memoryImageDestination) IgnoresEmbeddedDockerReference() bool {
	return true
}

func (mid *memoryImageDestination) PutBlob(ctx context.Context, stream io.Reader, inputInfo types.BlobInfo, cache types.BlobInfoCache, isConfig bool) (types.BlobInfo, error) {
	data, err := io.ReadAll(stream)
	if err != nil {
		return types.BlobInfo{}, err
	}
	digest := digest.FromBytes(data)
	mid.blobs[digest] = data
	return types.BlobInfo{Digest: digest, Size: int64(len(data))}, nil
}

func (mid *memoryImageDestination) HasThreadSafePutBlob() bool {
	return false
}

func (mid *memoryImageDestination) TryReusingBlob(ctx context.Context, info types.BlobInfo, cache types.BlobInfoCache, canSubstitute bool) (bool, types.BlobInfo, error) {
	if data, ok := mid.blobs[info.Digest]; ok {
		return true, types.BlobInfo{Digest: info.Digest, Size: int64(len(data))}, nil
	}
	return false, types.BlobInfo{}, nil
}

func (mid *memoryImageDestination) PutManifest(ctx context.Context, manifest []byte, instanceDigest *digest.Digest) error {
	mid.manifests[memoryInstanceKey(instanceDigest)] = manifest
	return nil
}

func (mid *memoryImageDestination) PutSignatures(ctx context.Context, signatures [][]byte, instanceDigest *digest.Digest) error {
	mid.signatures[memoryInstanceKey(instanceDigest)] = signatures
	return nil
}

func (mid *memoryImageDestination) Commit(ctx context.Context, unparsedToplevel types.UnparsedImage) error {
	return nil
}
