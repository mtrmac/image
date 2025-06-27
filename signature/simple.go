// Note: Consider the API unstable until the code supports at least three different image formats or transports.

// NOTE: Keep this in sync with docs/atomic-signature.md and docs/atomic-signature-embedded.json!

package signature

import (
	"encoding/json"
	"time"

	"github.com/containers/image/v5/signature/internal"
	digest "github.com/opencontainers/go-digest"
)

// InvalidSignatureError is returned when parsing an invalid signature.
type InvalidSignatureError = internal.InvalidSignatureError

// Signature is a parsed content of a signature.
type Signature = internal.Signature

// UntrustedSignatureInformation is information available in an untrusted signature.
// This may be useful when debugging signature verification failures,
// or when managing a set of signatures on a single image.
//
// WARNING: Do not use the contents of this for ANY security decisions,
// and be VERY CAREFUL about showing this information to humans in any way which suggest that these values “are probably” reliable.
// There is NO REASON to expect the values to be correct, or not intentionally misleading
// (including things like “✅ Verified by $authority”)
type UntrustedSignatureInformation struct {
	UntrustedDockerManifestDigest digest.Digest
	UntrustedDockerReference      string // FIXME: more precise type?
	UntrustedCreatorID            *string
	UntrustedTimestamp            *time.Time
	UntrustedShortKeyIdentifier   string
}

// GetUntrustedSignatureInformationWithoutVerifying extracts information available in an untrusted signature,
// WITHOUT doing any cryptographic verification.
// This may be useful when debugging signature verification failures,
// or when managing a set of signatures on a single image.
//
// WARNING: Do not use the contents of this for ANY security decisions,
// and be VERY CAREFUL about showing this information to humans in any way which suggest that these values “are probably” reliable.
// There is NO REASON to expect the values to be correct, or not intentionally misleading
// (including things like “✅ Verified by $authority”)
func GetUntrustedSignatureInformationWithoutVerifying(untrustedSignatureBytes []byte) (*UntrustedSignatureInformation, error) {
	// NOTE: This should eventually do format autodetection.
	mech, _, err := NewEphemeralGPGSigningMechanism([]byte{})
	if err != nil {
		return nil, err
	}
	defer mech.Close()

	untrustedContents, shortKeyIdentifier, err := mech.UntrustedSignatureContents(untrustedSignatureBytes)
	if err != nil {
		return nil, err
	}
	var untrustedDecodedContents internal.UntrustedSignature
	if err := json.Unmarshal(untrustedContents, &untrustedDecodedContents); err != nil {
		return nil, internal.NewInvalidSignatureError(err.Error())
	}

	var timestamp *time.Time // = nil
	if untrustedDecodedContents.UntrustedTimestamp != nil {
		ts := time.Unix(*untrustedDecodedContents.UntrustedTimestamp, 0)
		timestamp = &ts
	}
	return &UntrustedSignatureInformation{
		UntrustedDockerManifestDigest: untrustedDecodedContents.UntrustedDockerManifestDigest,
		UntrustedDockerReference:      untrustedDecodedContents.UntrustedDockerReference,
		UntrustedCreatorID:            untrustedDecodedContents.UntrustedCreatorID,
		UntrustedTimestamp:            timestamp,
		UntrustedShortKeyIdentifier:   shortKeyIdentifier,
	}, nil
}
