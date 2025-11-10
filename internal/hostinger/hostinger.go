//go:generate oapi-codegen -generate "types,client" -package "client" -o "../client/client.gen.go" "api-1.json"

package hostinger

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"context"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/cert-manager/webhook-example/internal/client"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// hostingerSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type hostingerSolver struct {
	client *kubernetes.Clientset
}

// hostingerConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type hostingerConfig struct {
	APITokenSecretRef cmmeta.SecretKeySelector `json:"apiTokenSecretRef"`
	ServerURL         string                   `json:"serverURL"`
}

// New returns a new instance of the hostingerSolver solver.
func New() webhook.Solver {
	return &hostingerSolver{}
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (s *hostingerSolver) Name() string {
	return "hostinger"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (s *hostingerSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	ctx := context.Background()
	hostingerClient, err := s.getHostingerClient(ctx, ch)
	if err != nil {
		return err
	}

	isZoneValid, err := validateZone(hostingerClient, ctx, ch.ResolvedZone)
	if err != nil {
		return err
	}

	if !isZoneValid {
		return errors.New("provided zone is invalid")
	}

	domain := util.UnFqdn(ch.ResolvedZone)
	subDomain := getSubDomain(domain, ch.ResolvedFQDN)
	target := ch.Key

	err = addTXTRecord(hostingerClient, ctx, domain, subDomain, target)
	if err != nil {
		return err
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (s *hostingerSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	ctx := context.Background()
	hostingerClient, err := s.getHostingerClient(ctx, ch)
	if err != nil {
		return err
	}

	domain := util.UnFqdn(ch.ResolvedZone)
	target := ch.Key

	return removeTXTRecords(hostingerClient, ctx, domain, target)
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (s *hostingerSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	s.client = cl
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (hostingerConfig, error) {
	cfg := hostingerConfig{}

	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// createClient creates a new Hostinger API client with authentication.
func createClient(serverURL string, apiToken string) (*client.ClientWithResponses, error) {
	authEditor := func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+apiToken)
		return nil
	}

	apiClient, err := client.NewClientWithResponses(
		serverURL,
		client.WithRequestEditorFn(authEditor),
	)

	if err != nil {
		return nil, err
	}

	return apiClient, nil
}

// listDNSRecords lists all DNS records for a given domain zone.
func listDNSRecords(hostingerClient *client.ClientWithResponses, ctx context.Context, domain client.Domain) (*client.DNSV1ZoneRecordCollection, error) {
	resp, err := hostingerClient.DNSGetDNSRecordsV1WithResponse(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("getting DNS records failed: %w", err)
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("getting DNS records returned non-success code: %s", resp.Status())
	}

	return resp.JSON200, nil
}

// validateZone checks if a given DNS zone exists and is accessible via the API.
func validateZone(hostingerClient *client.ClientWithResponses, ctx context.Context, domain client.Domain) (bool, error) {
	resp, err := hostingerClient.DNSGetDNSRecordsV1WithResponse(ctx, domain)
	if err != nil {
		return false, fmt.Errorf("validate DNS record failed: %w", err)
	}

	if resp.StatusCode() == 200 {
		return true, nil
	}

	if resp.StatusCode() == 404 {
		return false, nil
	}

	return false, fmt.Errorf("validate DNS record returned non-success code: %s", resp.Status())
}

// addTXTRecord creates a new TXT record in the specified domain zone.
func addTXTRecord(hostingerClient *client.ClientWithResponses, ctx context.Context, domain client.Domain, subdomain string, content string) error {

	overwriteFlag := true
	ttlPrimary := 60

	body := client.DNSUpdateDNSRecordsV1JSONRequestBody{
		Overwrite: &overwriteFlag,
		Zone: []struct {
			Name    string `json:"name"`
			Records []struct {
				Content string `json:"content"`
			} `json:"records"`
			Ttl  *int                                  `json:"ttl,omitempty"`
			Type client.DNSV1ZoneUpdateRequestZoneType `json:"type"`
		}{
			{
				Name: subdomain,
				Type: "TXT",
				Ttl:  &ttlPrimary,
				Records: []struct {
					Content string `json:"content"`
				}{
					{Content: content},
				},
			},
		},
	}

	resp, err := hostingerClient.DNSUpdateDNSRecordsV1WithResponse(ctx, domain, body)
	if err != nil {
		return err
	}

	if resp.StatusCode() != 200 {
		return fmt.Errorf("API error on addTXTRecord: status %s, body: %s", resp.Status(), string(resp.Body))
	}

	return nil
}

// removeTXTRecords finds and removes a specific TXT record by its content.
func removeTXTRecords(hostingerClient *client.ClientWithResponses, ctx context.Context, domain client.Domain, content string) error {
	zoneCollection, err := listDNSRecords(hostingerClient, ctx, domain)
	if err != nil {
		return err
	}

	for _, elm := range *zoneCollection {
		for _, v := range *elm.Records {
			trimmedContent := stripQuotes(*v.Content)

			if trimmedContent == content && *elm.Type == "TXT" {
				err := removeTXTRecord(hostingerClient, ctx, domain, *elm.Name)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// removeTXTRecord sends the API request to delete a TXT record by its subdomain name.
func removeTXTRecord(hostingerClient *client.ClientWithResponses, ctx context.Context, domain client.Domain, subdomain string) error {
	body := client.DNSDeleteDNSRecordsV1JSONRequestBody{
		Filters: []struct {
			Name string                                    `json:"name"`
			Type client.DNSV1ZoneDestroyRequestFiltersType `json:"type"`
		}{
			{
				Name: subdomain,
				Type: "TXT",
			},
		},
	}

	resp, err := hostingerClient.DNSDeleteDNSRecordsV1WithResponse(ctx, domain, body)
	if err != nil {
		return err
	}

	if resp.StatusCode() != 200 {
		return fmt.Errorf("API error on removeTXTRecord: status %s, body: %s", resp.Status(), string(resp.Body))
	}

	return nil
}

// getSubDomain extracts the subdomain part from an FQDN relative to its parent domain.
// e.g., ("example.com", "_acme-challenge.example.com.") -> "_acme-challenge"
func getSubDomain(domain, fqdn string) string {
	if idx := strings.Index(fqdn, "."+domain); idx != -1 {
		return fqdn[:idx]
	}

	return util.UnFqdn(fqdn)
}

// stripQuotes removes surrounding double quotes from a string.
// This is necessary because some DNS providers return TXT record content
// wrapped in quotes (e.g., `"challenge_key"` instead of `challenge_key`).
func stripQuotes(s string) string {
	s = strings.TrimPrefix(s, `"`)
	s = strings.TrimSuffix(s, `"`)
	return s
}

// getSecret retrieves a Kubernetes Secret value from a given namespace and selector.
func (s *hostingerSolver) getSecret(ctx context.Context, ref cmmeta.SecretKeySelector, namespace string) (string, error) {
	secret, err := s.client.CoreV1().Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, ref.Name, err)
	}

	tokenBytes, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s/%s", ref.Key, namespace, ref.Name)
	}

	return string(tokenBytes), nil
}

// getHostingerClient is a helper function that handles loading configuration,
// fetching the API secret from Kubernetes, and instantiating the API client.
func (s *hostingerSolver) getHostingerClient(ctx context.Context, ch *v1alpha1.ChallengeRequest) (*client.ClientWithResponses, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	apiToken, err := s.getSecret(ctx, cfg.APITokenSecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	hostingerClient, err := createClient(cfg.ServerURL, apiToken)
	if err != nil {
		return nil, fmt.Errorf("hostinger client creation failed: %w", err)
	}

	return hostingerClient, nil
}
