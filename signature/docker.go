// Note: Consider the API unstable until the code supports at least three different image formats or transports.

package signature

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/signature/internal"
	"github.com/opencontainers/go-digest"
)

// SignOptions includes optional parameters for signing container images.
type SignOptions struct {
	// Passphare to use when signing with the key identity.
	Passphrase string
}

// SignDockerManifest returns a signature for manifest as the specified dockerReference,
// using mech and keyIdentity, and the specified options.
func SignDockerManifestWithOptions(m []byte, dockerReference string, mech SigningMechanism, keyIdentity string, options *SignOptions) ([]byte, error) {
	var passphrase string
	if options != nil {
		passphrase = options.Passphrase
		// The gpgme implementation can’t use passphrase with \n; reject it here for consistent behavior.
		if strings.Contains(passphrase, "\n") {
			return nil, errors.New("invalid passphrase: must not contain a line break")
		}
	}

	var rawSigner func(input []byte) ([]byte, error)
	if newMech, ok := mech.(internal.SigningMechanismWithPassphrase); ok {
		rawSigner = (func(input []byte) ([]byte, error) {
			return newMech.SignWithPassphrase(input, keyIdentity, passphrase)
		})
	} else if passphrase != "" {
		return nil, errors.New("signing mechanism does not support passphrases")
	} else {
		rawSigner = func(input []byte) ([]byte, error) {
			return mech.Sign(input, keyIdentity)
		}
	}

	return internal.SignDockerManifest(m, dockerReference, rawSigner)
}

// SignDockerManifest returns a signature for manifest as the specified dockerReference,
// using mech and keyIdentity.
func SignDockerManifest(m []byte, dockerReference string, mech SigningMechanism, keyIdentity string) ([]byte, error) {
	return SignDockerManifestWithOptions(m, dockerReference, mech, keyIdentity, nil)
}

// VerifyDockerManifestSignature checks that unverifiedSignature uses expectedKeyIdentity to sign unverifiedManifest as expectedDockerReference,
// using mech.
func VerifyDockerManifestSignature(unverifiedSignature, unverifiedManifest []byte,
	expectedDockerReference string, mech SigningMechanism, expectedKeyIdentity string) (*Signature, error) {
	sig, _, err := VerifyImageManifestSignatureUsingKeyIdentityList(unverifiedSignature, unverifiedManifest, expectedDockerReference, mech, []string{expectedKeyIdentity})
	return sig, err
}

// VerifyImageManifestSignatureUsingKeyIdentityList checks that unverifiedSignature uses one of the expectedKeyIdentities
// to sign unverifiedManifest as expectedDockerReference, using mech. Returns the verified signature and the key identity that
// was used to verify it.
func VerifyImageManifestSignatureUsingKeyIdentityList(unverifiedSignature, unverifiedManifest []byte,
	expectedDockerReference string, mech SigningMechanism, expectedKeyIdentities []string) (*Signature, string, error) {
	expectedRef, err := reference.ParseNormalizedNamed(expectedDockerReference)
	if err != nil {
		return nil, "", err
	}
	var matchedKeyIdentity string
	sig, err := internal.VerifyAndExtractSignature(mech, unverifiedSignature, internal.SignatureAcceptanceRules{
		ValidateKeyIdentity: func(keyIdentity string) error {
			if !slices.Contains(expectedKeyIdentities, keyIdentity) {
				return internal.NewInvalidSignatureError(fmt.Sprintf("Signature by %s does not match expected fingerprints %v", keyIdentity, expectedKeyIdentities))
			}
			matchedKeyIdentity = keyIdentity
			return nil
		},
		ValidateSignedDockerReference: func(signedDockerReference string) error {
			signedRef, err := reference.ParseNormalizedNamed(signedDockerReference)
			if err != nil {
				return internal.NewInvalidSignatureError(fmt.Sprintf("Invalid docker reference %q in signature", signedDockerReference))
			}
			if signedRef.String() != expectedRef.String() {
				return internal.NewInvalidSignatureError(fmt.Sprintf("Docker reference %q does not match %q",
					signedDockerReference, expectedDockerReference))
			}
			return nil
		},
		ValidateSignedDockerManifestDigest: func(signedDockerManifestDigest digest.Digest) error {
			matches, err := manifest.MatchesDigest(unverifiedManifest, signedDockerManifestDigest)
			if err != nil {
				return err
			}
			if !matches {
				return internal.NewInvalidSignatureError(fmt.Sprintf("Signature for docker digest %q does not match", signedDockerManifestDigest))
			}
			return nil
		},
	})
	if err != nil {
		return nil, "", err
	}
	return sig, matchedKeyIdentity, err
}
