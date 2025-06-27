// Note: Consider the API unstable until the code supports at least three different image formats or transports.

// NOTE: Keep this in sync with docs/atomic-signature.md and docs/atomic-signature-embedded.json!

package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/containers/image/v5/version"
	digest "github.com/opencontainers/go-digest"
)

const (
	signatureType = "atomic container signature"
)

// Signature is a parsed content of a signature.
type Signature struct {
	// The only way to get this structure from a blob should be as a return value from a successful call to VerifyAndExtractSignature below.

	DockerManifestDigest digest.Digest
	DockerReference      string // FIXME: more precise type?
}

// UntrustedSignature is a parsed content of a signature.
type UntrustedSignature struct {
	UntrustedDockerManifestDigest digest.Digest
	UntrustedDockerReference      string // FIXME: more precise type?
	UntrustedCreatorID            *string
	// This is intentionally an int64; the native JSON float64 type would allow to represent _some_ sub-second precision,
	// but not nearly enough (with current timestamp values, a single unit in the last place is on the order of hundreds of nanoseconds).
	// So, this is explicitly an int64, and we reject fractional values. If we did need more precise timestamps eventually,
	// we would add another field, UntrustedTimestampNS int64.
	UntrustedTimestamp *int64
}

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

// NewUntrustedSignature returns an untrustedSignature object with
// the specified primary contents and appropriate metadata.
func NewUntrustedSignature(dockerManifestDigest digest.Digest, dockerReference string) UntrustedSignature {
	// Use intermediate variables for these values so that we can take their addresses.
	// Golang guarantees that they will have a new address on every execution.
	creatorID := "atomic " + version.Version
	timestamp := time.Now().Unix()
	return UntrustedSignature{
		UntrustedDockerManifestDigest: dockerManifestDigest,
		UntrustedDockerReference:      dockerReference,
		UntrustedCreatorID:            &creatorID,
		UntrustedTimestamp:            &timestamp,
	}
}

// A compile-time check that UntrustedSignature and *UntrustedSignature implements json.Marshaler
var _ json.Marshaler = UntrustedSignature{}
var _ json.Marshaler = (*UntrustedSignature)(nil)

// MarshalJSON implements the json.Marshaler interface.
func (s UntrustedSignature) MarshalJSON() ([]byte, error) {
	if s.UntrustedDockerManifestDigest == "" || s.UntrustedDockerReference == "" {
		return nil, errors.New("Unexpected empty signature content")
	}
	critical := map[string]any{
		"type":     signatureType,
		"image":    map[string]string{"docker-manifest-digest": s.UntrustedDockerManifestDigest.String()},
		"identity": map[string]string{"docker-reference": s.UntrustedDockerReference},
	}
	optional := map[string]any{}
	if s.UntrustedCreatorID != nil {
		optional["creator"] = *s.UntrustedCreatorID
	}
	if s.UntrustedTimestamp != nil {
		optional["timestamp"] = *s.UntrustedTimestamp
	}
	signature := map[string]any{
		"critical": critical,
		"optional": optional,
	}
	return json.Marshal(signature)
}

// A compile-time check that UntrustedSignature implements json.Unmarshaler
var _ json.Unmarshaler = (*UntrustedSignature)(nil)

// UnmarshalJSON implements the json.Unmarshaler interface
func (s *UntrustedSignature) UnmarshalJSON(data []byte) error {
	return JSONFormatToInvalidSignatureError(s.strictUnmarshalJSON(data))
}

// strictUnmarshalJSON is UnmarshalJSON, except that it may return the JSONFormatError error type.
// Splitting it into a separate function allows us to do the JSONFormatError → InvalidSignatureError in a single place, the caller.
func (s *UntrustedSignature) strictUnmarshalJSON(data []byte) error {
	var critical, optional json.RawMessage
	if err := ParanoidUnmarshalJSONObjectExactFields(data, map[string]any{
		"critical": &critical,
		"optional": &optional,
	}); err != nil {
		return err
	}

	var creatorID string
	var timestamp float64
	var gotCreatorID, gotTimestamp = false, false
	if err := ParanoidUnmarshalJSONObject(optional, func(key string) any {
		switch key {
		case "creator":
			gotCreatorID = true
			return &creatorID
		case "timestamp":
			gotTimestamp = true
			return &timestamp
		default:
			var ignore any
			return &ignore
		}
	}); err != nil {
		return err
	}
	if gotCreatorID {
		s.UntrustedCreatorID = &creatorID
	}
	if gotTimestamp {
		intTimestamp := int64(timestamp)
		if float64(intTimestamp) != timestamp {
			return NewInvalidSignatureError("Field optional.timestamp is not an integer")
		}
		s.UntrustedTimestamp = &intTimestamp
	}

	var t string
	var image, identity json.RawMessage
	if err := ParanoidUnmarshalJSONObjectExactFields(critical, map[string]any{
		"type":     &t,
		"image":    &image,
		"identity": &identity,
	}); err != nil {
		return err
	}
	if t != signatureType {
		return NewInvalidSignatureError(fmt.Sprintf("Unrecognized signature type %s", t))
	}

	var digestString string
	if err := ParanoidUnmarshalJSONObjectExactFields(image, map[string]any{
		"docker-manifest-digest": &digestString,
	}); err != nil {
		return err
	}
	digestValue, err := digest.Parse(digestString)
	if err != nil {
		return NewInvalidSignatureError(fmt.Sprintf(`invalid docker-manifest-digest value %q: %v`, digestString, err))
	}
	s.UntrustedDockerManifestDigest = digestValue

	return ParanoidUnmarshalJSONObjectExactFields(identity, map[string]any{
		"docker-reference": &s.UntrustedDockerReference,
	})
}

// Sign formats the signature and returns a blob signed using mech and keyIdentity
// (If it seems surprising that this is a method on untrustedSignature, note that there
// isn’t a good reason to think that a key used by the user is trusted by any component
// of the system just because it is a private key — actually the presence of a private key
// on the system increases the likelihood of an a successful attack on that private key
// on that particular system.)
func (s UntrustedSignature) Sign(mech SigningMechanism, keyIdentity string, passphrase string) ([]byte, error) {
	json, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	if newMech, ok := mech.(SigningMechanismWithPassphrase); ok {
		return newMech.SignWithPassphrase(json, keyIdentity, passphrase)
	}

	if passphrase != "" {
		return nil, errors.New("signing mechanism does not support passphrases")
	}

	return mech.Sign(json, keyIdentity)
}

// SignatureAcceptanceRules specifies how to decide whether an untrusted signature is acceptable.
// We centralize the actual parsing and data extraction in VerifyAndExtractSignature; this supplies
// the policy.  We use an object instead of supplying func parameters to VerifyAndExtractSignature
// because the functions have the same or similar types, so there is a risk of exchanging the functions;
// named members of this struct are more explicit.
type SignatureAcceptanceRules struct {
	ValidateKeyIdentity                func(string) error
	ValidateSignedDockerReference      func(string) error
	ValidateSignedDockerManifestDigest func(digest.Digest) error
}

// VerifyAndExtractSignature verifies that unverifiedSignature has been signed, and that its principal components
// match expected values, both as specified by rules, and returns it
func VerifyAndExtractSignature(mech SigningMechanism, unverifiedSignature []byte, rules SignatureAcceptanceRules) (*Signature, error) {
	signed, keyIdentity, err := mech.Verify(unverifiedSignature)
	if err != nil {
		return nil, err
	}
	if err := rules.ValidateKeyIdentity(keyIdentity); err != nil {
		return nil, err
	}

	var unmatchedSignature UntrustedSignature
	if err := json.Unmarshal(signed, &unmatchedSignature); err != nil {
		return nil, NewInvalidSignatureError(err.Error())
	}
	if err := rules.ValidateSignedDockerManifestDigest(unmatchedSignature.UntrustedDockerManifestDigest); err != nil {
		return nil, err
	}
	if err := rules.ValidateSignedDockerReference(unmatchedSignature.UntrustedDockerReference); err != nil {
		return nil, err
	}
	// SignatureAcceptanceRules have accepted this value.
	return &Signature{
		DockerManifestDigest: unmatchedSignature.UntrustedDockerManifestDigest,
		DockerReference:      unmatchedSignature.UntrustedDockerReference,
	}, nil
}
