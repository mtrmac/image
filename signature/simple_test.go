package signature

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetUntrustedSignatureInformationWithoutVerifying(t *testing.T) {
	signature, err := os.ReadFile("./fixtures/image.signature")
	require.NoError(t, err)
	// Successful parsing, all optional fields present
	info, err := GetUntrustedSignatureInformationWithoutVerifying(signature)
	require.NoError(t, err)
	assert.Equal(t, TestImageSignatureReference, info.UntrustedDockerReference)
	assert.Equal(t, TestImageManifestDigest, info.UntrustedDockerManifestDigest)
	assert.NotNil(t, info.UntrustedCreatorID)
	assert.Equal(t, "atomic ", *info.UntrustedCreatorID)
	assert.NotNil(t, info.UntrustedTimestamp)
	assert.Equal(t, time.Unix(1458239713, 0), *info.UntrustedTimestamp)
	assert.Equal(t, TestKeyShortID, info.UntrustedShortKeyIdentifier)
	// Successful parsing, no optional fields present
	signature, err = os.ReadFile("./fixtures/no-optional-fields.signature")
	require.NoError(t, err)
	// Successful parsing
	info, err = GetUntrustedSignatureInformationWithoutVerifying(signature)
	require.NoError(t, err)
	assert.Equal(t, TestImageSignatureReference, info.UntrustedDockerReference)
	assert.Equal(t, TestImageManifestDigest, info.UntrustedDockerManifestDigest)
	assert.Nil(t, info.UntrustedCreatorID)
	assert.Nil(t, info.UntrustedTimestamp)
	assert.Equal(t, TestKeyShortID, info.UntrustedShortKeyIdentifier)

	// Completely invalid signature.
	_, err = GetUntrustedSignatureInformationWithoutVerifying([]byte{})
	assert.Error(t, err)

	_, err = GetUntrustedSignatureInformationWithoutVerifying([]byte("invalid signature"))
	assert.Error(t, err)

	// Valid signature of non-JSON
	invalidBlobSignature, err := os.ReadFile("./fixtures/invalid-blob.signature")
	require.NoError(t, err)
	_, err = GetUntrustedSignatureInformationWithoutVerifying(invalidBlobSignature)
	assert.Error(t, err)
}
