package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
)

func useHostupTestServer(t *testing.T, handler http.Handler) {
	t.Helper()

	server := httptest.NewServer(handler)
	oldBase := hostupAPIBase
	oldClient := hostupHTTPClient

	hostupAPIBase = server.URL
	hostupHTTPClient = server.Client()

	t.Cleanup(func() {
		hostupAPIBase = oldBase
		hostupHTTPClient = oldClient
		server.Close()
	})
}

func TestCreateTXTRecordCreatesWhenMissing(t *testing.T) {
	var posted createRecordRequest
	useHostupTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}

		switch r.Method {
		case http.MethodGet:
			if r.URL.Path != "/dns-zones/zone_123/records" {
				t.Fatalf("unexpected GET path: %s", r.URL.Path)
			}
			if r.URL.Query().Get("type") != "TXT" || r.URL.Query().Get("name") != "_acme-challenge" {
				t.Fatalf("unexpected GET query: %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"records":[]}`))
		case http.MethodPost:
			if r.URL.Path != "/dns-zones/zone_123/records" {
				t.Fatalf("unexpected POST path: %s", r.URL.Path)
			}
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Fatalf("decode posted body: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	}))

	if err := createTXTRecord(log, "token", "zone_123", "_acme-challenge", "txt-value"); err != nil {
		t.Fatalf("createTXTRecord returned error: %v", err)
	}

	expected := createRecordRequest{Type: "TXT", Name: "_acme-challenge", Value: "txt-value", TTL: 60}
	if posted != expected {
		t.Fatalf("posted body mismatch: got %#v want %#v", posted, expected)
	}
}

func TestCreateTXTRecordSkipsExistingExactValue(t *testing.T) {
	postCount := 0
	useHostupTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"records":[{"id":"rec_1","type":"TXT","name":"_acme-challenge.example.com","value":"txt-value"}]}`))
		case http.MethodPost:
			postCount++
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	}))

	if err := createTXTRecord(log, "token", "zone_123", "_acme-challenge", "txt-value"); err != nil {
		t.Fatalf("createTXTRecord returned error: %v", err)
	}
	if postCount != 0 {
		t.Fatalf("expected no POST for existing value, got %d", postCount)
	}
}

func TestDeleteTXTRecordDeletesAllMatchingExactValues(t *testing.T) {
	var deleted []string
	useHostupTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"records":[{"id":"rec_1","type":"TXT","name":"_acme-challenge.example.com","value":"txt-value"},{"id":"rec_2","type":"TXT","name":"_acme-challenge.example.com","value":"other-value"},{"id":"rec_3","type":"TXT","name":"_acme-challenge.example.com","value":"txt-value"}]}`))
		case http.MethodDelete:
			deleted = append(deleted, filepath.Base(r.URL.Path))
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	}))

	if err := deleteTXTRecord(log, "token", "zone_123", "_acme-challenge", "txt-value"); err != nil {
		t.Fatalf("deleteTXTRecord returned error: %v", err)
	}

	expected := []string{"rec_1", "rec_3"}
	if !reflect.DeepEqual(deleted, expected) {
		t.Fatalf("deleted record IDs mismatch: got %#v want %#v", deleted, expected)
	}
}

func TestLoadConfigRequiresSecretSelectors(t *testing.T) {
	if _, err := loadConfig(nil); err == nil {
		t.Fatal("expected nil config to fail")
	}
}

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
