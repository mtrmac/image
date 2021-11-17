package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchema2ListFromManifest(t *testing.T) {
	validManifest, err := os.ReadFile(filepath.Join("fixtures", "v2list.manifest.json"))
	require.NoError(t, err)

	// Invalid manifest version is rejected
	m, err := Schema2ListFromManifest(validManifest)
	require.NoError(t, err)
	m.SchemaVersion = 1
	manifest, err := m.Serialize()
	require.NoError(t, err)
	_, err = Schema2ListFromManifest(manifest)
	assert.Error(t, err)

	parser := func(m []byte) error {
		_, err := Schema2ListFromManifest(m)
		return err
	}
	// Schema mismatch is rejected
	testManifestFixturesAreRejected(t, parser, []string{
		"schema2-to-schema1-by-docker.json",
		"v2s2.manifest.json",
		"ociv1.manifest.json", "ociv1.image.index.json",
	})
	// Extra fields are rejected
	testValidManifestWithExtraFieldsIsRejected(t, parser, validManifest, []string{"config", "fsLayers", "history", "layers"})
}
