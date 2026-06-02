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

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

const hostupAPIBase = "https://cloud.hostup.se/api/v2"

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
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	apiKey, zoneID, err := c.credentials(cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}
	return createTXTRecord(apiKey, zoneID, recordName(ch.ResolvedFQDN, ch.ResolvedZone), ch.Key)
}

func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	apiKey, zoneID, err := c.credentials(cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}
	return deleteTXTRecord(apiKey, zoneID, recordName(ch.ResolvedFQDN, ch.ResolvedZone), ch.Key)
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
	apiKeySecret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), cfg.APIKeySecretRef.Name, metav1.GetOptions{})
	if err != nil {
		return "", "", err
	}
	apiKeyBytes, ok := apiKeySecret.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		return "", "", fmt.Errorf("key %q not found in secret %q", cfg.APIKeySecretRef.Key, cfg.APIKeySecretRef.Name)
	}

	zoneIDSecret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), cfg.ZoneIDKey.Name, metav1.GetOptions{})
	if err != nil {
		return "", "", err
	}
	zoneIDBytes, ok := zoneIDSecret.Data[cfg.ZoneIDKey.Key]
	if !ok {
		return "", "", fmt.Errorf("key %q not found in secret %q", cfg.ZoneIDKey.Key, cfg.ZoneIDKey.Name)
	}

	return string(apiKeyBytes), string(zoneIDBytes), nil
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
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

func createTXTRecord(apiKey, zoneID, name, value string) error {
	payload, err := json.Marshal(createRecordRequest{
		Type:  "TXT",
		Name:  name,
		Value: value,
		TTL:   60,
	})
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/dns-zones/%s/records", hostupAPIBase, zoneID)
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

func deleteTXTRecord(apiKey, zoneID, name, value string) error {
	params := url.Values{}
	params.Set("type", "TXT")
	params.Set("name", name)
	endpoint := fmt.Sprintf("%s/dns-zones/%s/records?%s", hostupAPIBase, zoneID, params.Encode())
	resp, err := hostupRequest(http.MethodGet, endpoint, apiKey, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hostup: list records returned %d: %s", resp.StatusCode, body)
	}
	var result listRecordsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("hostup: decode list response: %w", err)
	}
	for _, rec := range result.Records {
		if rec.Value == value {
			return deleteRecord(apiKey, zoneID, rec.ID)
		}
	}
	return nil
}

func deleteRecord(apiKey, zoneID, recordID string) error {
	endpoint := fmt.Sprintf("%s/dns-zones/%s/records/%s", hostupAPIBase, zoneID, recordID)
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
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	return cfg, nil
}
