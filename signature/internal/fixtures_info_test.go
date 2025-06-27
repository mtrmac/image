package internal

import "github.com/opencontainers/go-digest"

const (
	// TestImageManifestDigest is the Docker manifest digest of "image.manifest.json"
	TestImageManifestDigest = digest.Digest("sha256:20bf21ed457b390829cdbeec8795a7bea1626991fda603e0d01b4e7f60427e55")
	// TestImageSignatureReference is the Docker image reference signed in "image.signature"
	TestImageSignatureReference = "testing/manifest"

	// TestKeyFingerprint is the fingerprint of the private key in testGPGHomeDirectory.
	TestKeyFingerprint = "08CD26E446E2E95249B7A405E932F44B23E8DD43"
	// TestKeyShortID is the short ID of the private key in testGPGHomeDirectory.
	TestKeyShortID = "E932F44B23E8DD43"
	// TestKeyFingerprintWithPassphrase is the fingerprint of the private key with passphrase in testGPGHomeDirectory.
	TestKeyFingerprintWithPassphrase = "F2B501009F78B0B340221A12A3CD242DA6028093"
	// TestPassphrase is the passphrase for TestKeyFingerprintWithPassphrase.
	TestPassphrase = "WithPassphrase123"

	// TestSigstoreManifestDigest is the manifest digest of "valid.signature"
	TestSigstoreManifestDigest = digest.Digest("sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00")
	// TestSigstoreSignatureReference is the Docker reference signed in "valid.signature"
	TestSigstoreSignatureReference = "192.168.64.2:5000/cosign-signed-single-sample"
)
