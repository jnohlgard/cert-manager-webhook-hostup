package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
)

func TestRunsSuite(t *testing.T) {
	apiKey := os.Getenv("TEST_HOSTUP_API_KEY")
	zoneID := os.Getenv("TEST_HOSTUP_ZONE_ID")
	zone := os.Getenv("TEST_ZONE_NAME")

	if apiKey == "" || zoneID == "" || zone == "" {
		t.Skip("TEST_HOSTUP_API_KEY, TEST_HOSTUP_ZONE_ID, and TEST_ZONE_NAME must be set")
	}

	dir := t.TempDir()

	configJSON := []byte(`{
  "apiKeySecretRef": {"name": "hostup-credentials", "key": "apiKey"},
  "zoneIDKey":       {"name": "hostup-credentials", "key": "zoneId"}
}`)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), configJSON, 0644); err != nil {
		t.Fatal(err)
	}

	secretManifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: hostup-credentials
type: Opaque
data:
  apiKey: %s
  zoneId: %s
`, base64.StdEncoding.EncodeToString([]byte(apiKey)), base64.StdEncoding.EncodeToString([]byte(zoneID)))
	if err := os.WriteFile(filepath.Join(dir, "secret.yaml"), []byte(secretManifest), 0644); err != nil {
		t.Fatal(err)
	}

	fixture := acmetest.NewFixture(&customDNSProviderSolver{},
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath(dir),
	)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}
