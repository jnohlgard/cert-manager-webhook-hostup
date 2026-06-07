package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

var (
	hostupAPIBase    = "https://cloud.hostup.se/api/v2"
	hostupHTTPClient = &http.Client{Timeout: 15 * time.Second}
	log              = logf.Log.WithName("hostup-solver")
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}
	cmd.RunWebhookServer(GroupName, &customDNSProviderSolver{})
}

type customDNSProviderSolver struct {
	client kubernetes.Interface
}

type secretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type customDNSProviderConfig struct {
	APIKeySecretRef secretKeySelector `json:"apiKeySecretRef"`
	ZoneIDKey       secretKeySelector `json:"zoneIDKey"`
}

func (c *customDNSProviderSolver) Name() string {
	return "hostup"
}

func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	log := log.WithValues("fqdn", ch.ResolvedFQDN, "zone", ch.ResolvedZone, "namespace", ch.ResourceNamespace)
	log.Info("presenting DNS challenge")
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	apiKey, zoneID, err := c.credentials(cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}
	name := recordName(ch.ResolvedFQDN, ch.ResolvedZone)
	log.Info("creating TXT record", "recordName", name, "zoneID", zoneID)
	if err := createTXTRecord(log, apiKey, zoneID, name, ch.Key); err != nil {
		log.Error(err, "failed to create TXT record", "recordName", name, "zoneID", zoneID)
		return err
	}
	log.Info("DNS challenge presented successfully")
	return nil
}

func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	log := log.WithValues("fqdn", ch.ResolvedFQDN, "zone", ch.ResolvedZone, "namespace", ch.ResourceNamespace)
	log.Info("cleaning up DNS challenge")
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	apiKey, zoneID, err := c.credentials(cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}
	name := recordName(ch.ResolvedFQDN, ch.ResolvedZone)
	log.Info("deleting TXT record", "recordName", name, "zoneID", zoneID)
	if err := deleteTXTRecord(log, apiKey, zoneID, name, ch.Key); err != nil {
		log.Error(err, "failed to delete TXT record", "recordName", name, "zoneID", zoneID)
		return err
	}
	log.Info("DNS challenge cleaned up successfully")
	return nil
}

func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.client = cl
	return nil
}

func (c *customDNSProviderSolver) credentials(cfg customDNSProviderConfig, namespace string) (apiKey, zoneID string, err error) {
	log.V(1).Info("fetching API key secret", "secret", cfg.APIKeySecretRef.Name, "key", cfg.APIKeySecretRef.Key, "namespace", namespace)
	apiKeySecret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), cfg.APIKeySecretRef.Name, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("failed to get API key secret %q in namespace %q: %w", cfg.APIKeySecretRef.Name, namespace, err)
	}
	apiKeyBytes, ok := apiKeySecret.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		return "", "", fmt.Errorf("key %q not found in secret %q", cfg.APIKeySecretRef.Key, cfg.APIKeySecretRef.Name)
	}

	log.V(1).Info("fetching zone ID secret", "secret", cfg.ZoneIDKey.Name, "key", cfg.ZoneIDKey.Key, "namespace", namespace)
	zoneIDSecret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), cfg.ZoneIDKey.Name, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("failed to get zone ID secret %q in namespace %q: %w", cfg.ZoneIDKey.Name, namespace, err)
	}
	zoneIDBytes, ok := zoneIDSecret.Data[cfg.ZoneIDKey.Key]
	if !ok {
		return "", "", fmt.Errorf("key %q not found in secret %q", cfg.ZoneIDKey.Key, cfg.ZoneIDKey.Name)
	}

	apiKey = strings.TrimSpace(string(apiKeyBytes))
	zoneID = strings.TrimSpace(string(zoneIDBytes))
	if apiKey == "" {
		return "", "", fmt.Errorf("key %q in secret %q is empty", cfg.APIKeySecretRef.Key, cfg.APIKeySecretRef.Name)
	}
	if zoneID == "" {
		return "", "", fmt.Errorf("key %q in secret %q is empty", cfg.ZoneIDKey.Key, cfg.ZoneIDKey.Name)
	}

	return apiKey, zoneID, nil
}

// recordName returns the record name relative to the zone (no trailing dot).
func recordName(fqdn, zone string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")
	name := strings.TrimSuffix(fqdn, "."+zone)
	if name == zone {
		return "@"
	}
	return name
}

// --- Hostup API types ---

type dnsRecord struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type createRecordRequest struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

type listRecordsResponse struct {
	Records []dnsRecord `json:"records"`
}

// --- Hostup API calls ---

func hostupRequest(method, endpoint, apiKey string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return hostupHTTPClient.Do(req)
}

func createTXTRecord(log logr.Logger, apiKey, zoneID, name, value string) error {
	existingIDs, err := findTXTRecordIDs(log, apiKey, zoneID, name, value)
	if err != nil {
		return err
	}
	if len(existingIDs) > 0 {
		return nil
	}

	payload, err := json.Marshal(createRecordRequest{
		Type:  "TXT",
		Name:  name,
		Value: value,
		TTL:   60,
	})
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/dns-zones/%s/records", hostupAPIBase, url.PathEscape(zoneID))
	log.V(1).Info("sending create record request", "endpoint", endpoint)
	resp, err := hostupRequest(http.MethodPost, endpoint, apiKey, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hostup: create record returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

func deleteTXTRecord(log logr.Logger, apiKey, zoneID, name, value string) error {
	recordIDs, err := findTXTRecordIDs(log, apiKey, zoneID, name, value)
	if err != nil {
		return err
	}
	for _, recordID := range recordIDs {
		if err := deleteRecord(log, apiKey, zoneID, recordID); err != nil {
			return err
		}
	}
	log.Info("no matching TXT record found, nothing to delete")
	return nil
}

func findTXTRecordIDs(log logr.Logger, apiKey, zoneID, name, value string) ([]string, error) {
	params := url.Values{}
	params.Set("type", "TXT")
	params.Set("name", name)
	endpoint := fmt.Sprintf("%s/dns-zones/%s/records?%s", hostupAPIBase, url.PathEscape(zoneID), params.Encode())
	log.V(1).Info("listing TXT records", "endpoint", endpoint)
	resp, err := hostupRequest(http.MethodGet, endpoint, apiKey, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hostup: list records returned %d: %s", resp.StatusCode, body)
	}
	var result listRecordsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("hostup: decode list response: %w", err)
	}
	log.V(1).Info("listed TXT records", "count", len(result.Records))

	var ids []string
	for _, rec := range result.Records {
		if rec.Type != "" && rec.Type != "TXT" {
			continue
		}
		if rec.Value == value && rec.ID != "" {
			ids = append(ids, rec.ID)
		}
	}
	return ids, nil
}

func deleteRecord(log logr.Logger, apiKey, zoneID, recordID string) error {
	endpoint := fmt.Sprintf("%s/dns-zones/%s/records/%s", hostupAPIBase, url.PathEscape(zoneID), url.PathEscape(recordID))
	log.V(1).Info("sending delete record request", "endpoint", endpoint)
	resp, err := hostupRequest(http.MethodDelete, endpoint, apiKey, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hostup: delete record returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, fmt.Errorf("solver config is required")
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	if cfg.APIKeySecretRef.Name == "" || cfg.APIKeySecretRef.Key == "" {
		return cfg, fmt.Errorf("apiKeySecretRef.name and apiKeySecretRef.key are required")
	}
	if cfg.ZoneIDKey.Name == "" || cfg.ZoneIDKey.Key == "" {
		return cfg, fmt.Errorf("zoneIDKey.name and zoneIDKey.key are required")
	}
	return cfg, nil
}
