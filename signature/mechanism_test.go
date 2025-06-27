package signature

// These tests are expected to pass unmodified for _all_ of mechanism_sequoia.go, mechanism_gpgme.go, and mechanism_openpgp.go.

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testGPGHomeDirectory = "./fixtures"
)

// Many of the tests use two fixtures: V4 signature packets (*.signature), and V3 signature packets (*.signature-v3)

// fixtureVariants loads V3 and V4 signature fixture variants based on the v4 fixture path, and returns a map which makes it easy to test both.
func fixtureVariants(t *testing.T, v4Path string) map[string][]byte {
	v4, err := os.ReadFile(v4Path)
	require.NoError(t, err)
	v3Path := v4Path + "-v3"
	v3, err := os.ReadFile(v3Path)
	require.NoError(t, err)
	return map[string][]byte{v4Path: v4, v3Path: v3}
}

func TestNewGPGSigningMechanism(t *testing.T) {
	// A dumb test just for code coverage. We test more with internal.NewGPGSigningMechanismInDirectory().
	mech, err := NewGPGSigningMechanism()
	assert.NoError(t, err)
	mech.Close()
}

func TestNewEphemeralGPGSigningMechanism(t *testing.T) {
	// Empty input: This is accepted anyway by GPG, just returns no keys.
	mech, keyIdentities, err := NewEphemeralGPGSigningMechanism([]byte{})
	require.NoError(t, err)
	defer mech.Close()
	assert.Empty(t, keyIdentities)
	// Try validating a signature when the key is unknown.
	signatures := fixtureVariants(t, "./fixtures/invalid-blob.signature")
	for version, signature := range signatures {
		_, _, err := mech.Verify(signature)
		require.Error(t, err, version)
	}

	// Successful import
	keyBlob, err := os.ReadFile("./fixtures/public-key.gpg")
	require.NoError(t, err)
	mech, keyIdentities, err = NewEphemeralGPGSigningMechanism(keyBlob)
	require.NoError(t, err)
	defer mech.Close()
	assert.Equal(t, []string{TestKeyFingerprint}, keyIdentities)
	// After import, the signature should validate.
	for version, signature := range signatures {
		content, signingFingerprint, err := mech.Verify(signature)
		require.NoError(t, err, version)
		assert.Equal(t, []byte("This is not JSON\n"), content, version)
		assert.Equal(t, TestKeyFingerprint, signingFingerprint, version)
	}

	// Two keys in a keyring: Read the binary-format pubring.gpg, and concatenate it twice.
	// (Using two copies of public-key.gpg, in the ASCII-armored format, works with
	// gpgmeSigningMechanism but not openpgpSigningMechanism.)
	keyBlob, err = os.ReadFile("./fixtures/pubring.gpg")
	require.NoError(t, err)
	mech, keyIdentities, err = NewEphemeralGPGSigningMechanism(bytes.Join([][]byte{keyBlob, keyBlob}, nil))
	require.NoError(t, err)
	defer mech.Close()
	assert.Equal(t, []string{TestKeyFingerprintWithPassphrase, TestKeyFingerprint, TestKeyFingerprintWithPassphrase, TestKeyFingerprint}, keyIdentities)

	// Invalid input: This is, sadly, accepted anyway by GPG, just returns no keys.
	// For openpgpSigningMechanism we can detect this and fail.
	mech, keyIdentities, err = NewEphemeralGPGSigningMechanism([]byte("This is invalid"))
	assert.True(t, err != nil || len(keyIdentities) == 0)
	if err == nil {
		mech.Close()
	}
	assert.Empty(t, keyIdentities)
	// The various GPG/GPGME failures cases are not obviously easy to reach.
}
