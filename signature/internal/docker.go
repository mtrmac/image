package internal

import (
	"github.com/containers/image/v5/manifest"
)

// SignDockerManifest returns a signature for manifest as the specified dockerReference,
// using rawSigner.
// FIXME: eventually, rename
func SignDockerManifest(m []byte, dockerReference string, rawSigner func(input []byte) ([]byte, error)) ([]byte, error) {
	manifestDigest, err := manifest.Digest(m)
	if err != nil {
		return nil, err
	}
	sig := NewUntrustedSignature(manifestDigest, dockerReference)
	return sig.Sign(rawSigner)
}
