// Note: Consider the API unstable until the code supports at least three different image formats or transports.

package signature

import (
	"github.com/containers/image/v5/signature/internal"
)

// SigningMechanism abstracts a way to sign binary blobs and verify their signatures.
// Each mechanism should eventually be closed by calling Close().
type SigningMechanism interface {
	// Close removes resources associated with the mechanism, if any.
	Close() error
	// SupportsSigning returns nil if the mechanism supports signing, or a SigningNotSupportedError.
	SupportsSigning() error
	// Sign creates a (non-detached) signature of input using keyIdentity.
	// Fails with a SigningNotSupportedError if the mechanism does not support signing.
	Sign(input []byte, keyIdentity string) ([]byte, error)
	// Verify parses unverifiedSignature and returns the content and the signer's identity
	Verify(unverifiedSignature []byte) (contents []byte, keyIdentity string, err error)
	// UntrustedSignatureContents returns UNTRUSTED contents of the signature WITHOUT ANY VERIFICATION,
	// along with a short identifier of the key used for signing.
	// WARNING: The short key identifier (which corresponds to "Key ID" for OpenPGP keys)
	// is NOT the same as a "key identity" used in other calls to this interface, and
	// the values may have no recognizable relationship if the public key is not available.
	UntrustedSignatureContents(untrustedSignature []byte) (untrustedContents []byte, shortKeyIdentifier string, err error)
}

// SigningNotSupportedError is returned when trying to sign using a mechanism which does not support that.
type SigningNotSupportedError = internal.SigningNotSupportedError

// NewGPGSigningMechanism returns a new GPG/OpenPGP signing mechanism for the user’s default
// GPG configuration ($GNUPGHOME / ~/.gnupg)
// The caller must call .Close() on the returned SigningMechanism.
func NewGPGSigningMechanism() (SigningMechanism, error) {
	return internal.NewGPGSigningMechanismInDirectory("")
}

// NewEphemeralGPGSigningMechanism returns a new GPG/OpenPGP signing mechanism which
// recognizes _only_ public keys from the supplied blob, and returns the identities
// of these keys.
// The caller must call .Close() on the returned SigningMechanism.
func NewEphemeralGPGSigningMechanism(blob []byte) (SigningMechanism, []string, error) {
	return internal.NewEphemeralGPGSigningMechanism([][]byte{blob})
}
