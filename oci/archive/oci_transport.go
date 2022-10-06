package archive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/containers/image/v5/directory/explicitfilepath"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/internal/image"
	"github.com/containers/image/v5/internal/tmpdir"
	"github.com/containers/image/v5/oci/internal"
	ocilayout "github.com/containers/image/v5/oci/layout"
	"github.com/containers/image/v5/transports"
	"github.com/containers/image/v5/types"
	"github.com/containers/storage/pkg/archive"
)

func init() {
	transports.Register(Transport)
}

var invalidOciArchiveErr error = errors.New("Invalid oci-archive: reference")

// Transport is an ImageTransport for OCI archive
// it creates an oci-archive tar file by calling into the OCI transport
// tarring the directory created by oci and deleting the directory
var Transport = ociArchiveTransport{}

type ociArchiveTransport struct{}

// ociArchiveReference is an ImageReference for OCI Archive paths
type ociArchiveReference struct {
	file          string
	resolvedFile  string
	image         string
	sourceIndex   int
	archiveReader *Reader
	archiveWriter *Writer
}

func (t ociArchiveTransport) Name() string {
	return "oci-archive"
}

// ParseReference converts a string, which should not start with the ImageTransport.Name prefix
// into an ImageReference.
func (t ociArchiveTransport) ParseReference(reference string) (types.ImageReference, error) {
	return ParseReference(reference)
}

// ValidatePolicyConfigurationScope checks that scope is a valid name for a signature.PolicyTransportScopes keys
func (t ociArchiveTransport) ValidatePolicyConfigurationScope(scope string) error {
	return internal.ValidateScope(scope)
}

// ParseReference converts a string, which should not start with the ImageTransport.Name prefix, into an OCI ImageReference.
func ParseReference(reference string) (types.ImageReference, error) {
	file, image, index, err := internal.ParseReferenceIntoElements(reference)
	if err != nil {
		return nil, err
	}
	return newReference(file, image, index, nil, nil)
}

// NewReference returns an OCI reference for a file and an image.
func NewReference(file, image string) (types.ImageReference, error) {
	return newReference(file, image, -1, nil, nil)
}

// NewIndexReference returns an OCI reference for a file and a zero-based source manifest index.
func NewIndexReference(file string, sourceIndex int) (types.ImageReference, error) {
	return newReference(file, "", sourceIndex, nil, nil)
}

func newReference(file, image string, sourceIndex int, archiveReader *Reader, archiveWriter *Writer) (types.ImageReference, error) {
	resolved, err := explicitfilepath.ResolvePathToFullyExplicit(file)
	if err != nil {
		return nil, err
	}

	if err := internal.ValidateOCIPath(file); err != nil {
		return nil, err
	}

	if err := internal.ValidateImageName(image); err != nil {
		return nil, err
	}

	if sourceIndex != -1 && sourceIndex < 0 {
		return nil, fmt.Errorf("index @%d must not be negative: %w", sourceIndex, invalidOciArchiveErr)
	}
	if sourceIndex != -1 && image != "" {
		return nil, fmt.Errorf("cannot set image %s and index @%d at the same time: %w", image, sourceIndex, invalidOciArchiveErr)
	}
	return ociArchiveReference{
		file:          file,
		resolvedFile:  resolved,
		image:         image,
		sourceIndex:   sourceIndex,
		archiveReader: archiveReader,
		archiveWriter: archiveWriter,
	}, nil
}

func (ref ociArchiveReference) Transport() types.ImageTransport {
	return Transport
}

// StringWithinTransport returns a string representation of the reference, which MUST be such that
// reference.Transport().ParseReference(reference.StringWithinTransport()) returns an equivalent reference.
func (ref ociArchiveReference) StringWithinTransport() string {
	if ref.sourceIndex == -1 {
		return fmt.Sprintf("%s:%s", ref.file, ref.image)
	}
	return fmt.Sprintf("%s:@%d", ref.file, ref.sourceIndex)
}

// DockerReference returns a Docker reference associated with this reference
func (ref ociArchiveReference) DockerReference() reference.Named {
	return nil
}

// PolicyConfigurationIdentity returns a string representation of the reference, suitable for policy lookup.
func (ref ociArchiveReference) PolicyConfigurationIdentity() string {
	// NOTE: ref.image is not a part of the image identity, because "$dir:$someimage" and "$dir:" may mean the
	// same image and the two can’t be statically disambiguated.  Using at least the repository directory is
	// less granular but hopefully still useful.
	return ref.resolvedFile
}

// PolicyConfigurationNamespaces returns a list of other policy configuration namespaces to search
// for if explicit configuration for PolicyConfigurationIdentity() is not set
func (ref ociArchiveReference) PolicyConfigurationNamespaces() []string {
	res := []string{}
	path := ref.resolvedFile
	for {
		lastSlash := strings.LastIndex(path, "/")
		// Note that we do not include "/"; it is redundant with the default "" global default,
		// and rejected by ociTransport.ValidatePolicyConfigurationScope above.
		if lastSlash == -1 || path == "/" {
			break
		}
		res = append(res, path)
		path = path[:lastSlash]
	}
	return res
}

// NewImage returns a types.ImageCloser for this reference, possibly specialized for this ImageTransport.
// The caller must call .Close() on the returned ImageCloser.
// NOTE: If any kind of signature verification should happen, build an UnparsedImage from the value returned by NewImageSource,
// verify that UnparsedImage, and convert it into a real Image via image.FromUnparsedImage.
// WARNING: This may not do the right thing for a manifest list, see image.FromSource for details.
func (ref ociArchiveReference) NewImage(ctx context.Context, sys *types.SystemContext) (types.ImageCloser, error) {
	return image.FromReference(ctx, sys, ref)
}

// NewImageSource returns a types.ImageSource for this reference.
// The caller must call .Close() on the returned ImageSource.
func (ref ociArchiveReference) NewImageSource(ctx context.Context, sys *types.SystemContext) (types.ImageSource, error) {
	return newImageSource(ctx, sys, ref)
}

// NewImageDestination returns a types.ImageDestination for this reference.
// The caller must call .Close() on the returned ImageDestination.
func (ref ociArchiveReference) NewImageDestination(ctx context.Context, sys *types.SystemContext) (types.ImageDestination, error) {
	return newImageDestination(ctx, sys, ref)
}

// DeleteImage deletes the named image from the registry, if supported.
func (ref ociArchiveReference) DeleteImage(ctx context.Context, sys *types.SystemContext) error {
	return errors.New("Deleting images not implemented for oci: images")
}

// struct to store the ociReference and temporary directory returned by createOCIRef
type tempDirOCIRef struct {
	tempDirectory   string
	ociRefExtracted types.ImageReference
}

// deletes the temporary directory created
func (t *tempDirOCIRef) deleteTempDir() error {
	return os.RemoveAll(t.tempDirectory)
}

// createOCIRef creates the oci reference of the image
// If SystemContext.BigFilesTemporaryDir not "", overrides the temporary directory to use for storing big files
func createOCIRef(sys *types.SystemContext, image string, sourceIndex int) (tempDirOCIRef, error) {
	dir, err := os.MkdirTemp(tmpdir.TemporaryDirectoryForBigFiles(sys), "oci")
	if err != nil {
		return tempDirOCIRef{}, fmt.Errorf("creating temp directory: %w", err)
	}
	var ociRef types.ImageReference
	if sourceIndex > -1 {
		if ociRef, err = ocilayout.NewIndexReference(dir, sourceIndex); err != nil {
			return tempDirOCIRef{}, err
		}
	} else {
		if ociRef, err = ocilayout.NewReference(dir, image); err != nil {
			return tempDirOCIRef{}, err
		}
	}

	tempDirRef := tempDirOCIRef{tempDirectory: dir, ociRefExtracted: ociRef}
	return tempDirRef, nil
}

// creates the temporary directory and copies the tarred content to it
func createUntarTempDir(sys *types.SystemContext, ref ociArchiveReference) (tempDirOCIRef, error) {
	tempDirRef, err := createOCIRef(sys, ref.image, ref.sourceIndex)
	if err != nil {
		return tempDirOCIRef{}, fmt.Errorf("creating oci reference: %w", err)
	}
	src := ref.resolvedFile
	dst := tempDirRef.tempDirectory
	// TODO: This can take quite some time, and should ideally be cancellable using a context.Context.
	arch, err := os.Open(src)
	if err != nil {
		return tempDirOCIRef{}, err
	}
	defer arch.Close()
	if err := archive.NewDefaultArchiver().Untar(arch, dst, &archive.TarOptions{NoLchown: true}); err != nil {
		if err := tempDirRef.deleteTempDir(); err != nil {
			return tempDirOCIRef{}, fmt.Errorf("deleting temp directory %q: %w", tempDirRef.tempDirectory, err)
		}
		return tempDirOCIRef{}, fmt.Errorf("untarring file %q: %w", tempDirRef.tempDirectory, err)
	}
	return tempDirRef, nil
}
