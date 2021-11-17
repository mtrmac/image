package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOCI1IndexFromManifest(t *testing.T) {
	validManifest, err := os.ReadFile(filepath.Join("fixtures", "ociv1.image.index.json"))
	require.NoError(t, err)

	// Invalid manifest version is rejected
	m, err := OCI1IndexFromManifest(validManifest)
	require.NoError(t, err)
	m.SchemaVersion = 1
	manifest, err := m.Serialize()
	require.NoError(t, err)
	_, err = OCI1IndexFromManifest(manifest)
	assert.Error(t, err)

	parser := func(m []byte) error {
		_, err := OCI1IndexFromManifest(m)
		return err
	}
	// Schema mismatch is rejected
	testManifestFixturesAreRejected(t, parser, []string{
		"schema2-to-schema1-by-docker.json",
		"v2s2.manifest.json", "v2list.manifest.json",
		"ociv1.manifest.json",
	})
	// Extra fields are rejected
	testValidManifestWithExtraFieldsIsRejected(t, parser, validManifest, []string{"config", "fsLayers", "history", "layers"})
}
