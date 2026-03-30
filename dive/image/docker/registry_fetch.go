package docker

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	cliconfig "github.com/docker/cli/cli/config"
	"github.com/distribution/reference"
	"github.com/wagoodman/dive/internal/log"
)

type registryClient struct {
	registry string
	repo     string
	username string
	password string
	token    string
	client   *http.Client
}

func newRegistryBlobFetcher(imageRef string) (BlobFetcher, error) {
	rc, err := newRegistryClient(imageRef)
	if err != nil {
		return nil, err
	}
	return rc.fetchBlob, nil
}

func newRegistryClient(imageRef string) (*registryClient, error) {
	named, err := reference.ParseNormalizedNamed(imageRef)
	if err != nil {
		return nil, fmt.Errorf("could not parse image reference %q: %w", imageRef, err)
	}

	domain := reference.Domain(named)
	repo := reference.Path(named)

	rc := &registryClient{
		registry: domain,
		repo:     repo,
		client:   &http.Client{},
	}

	cf, err := cliconfig.Load(cliconfig.Dir())
	if err != nil {
		return nil, fmt.Errorf("could not load docker config: %w", err)
	}

	authConfig, err := cf.GetAuthConfig(domain)
	if err != nil {
		return nil, fmt.Errorf("could not get auth config for %s: %w", domain, err)
	}
	rc.username = authConfig.Username
	rc.password = authConfig.Password

	if err := rc.authenticate(); err != nil {
		return nil, err
	}

	return rc, nil
}

func (rc *registryClient) authenticate() error {
	resp, err := rc.client.Get(fmt.Sprintf("https://%s/v2/", rc.registry))
	if err != nil {
		return fmt.Errorf("could not reach registry %s: %w", rc.registry, err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("unexpected status %d from registry %s", resp.StatusCode, rc.registry)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	realm, service, err := parseWWWAuthenticate(wwwAuth)
	if err != nil {
		return fmt.Errorf("could not parse registry auth challenge: %w", err)
	}

	tokenURL := fmt.Sprintf("%s?service=%s&scope=repository:%s:pull", realm, service, rc.repo)
	req, err := http.NewRequest("GET", tokenURL, nil)
	if err != nil {
		return err
	}

	if rc.username != "" && rc.password != "" {
		req.SetBasicAuth(rc.username, rc.password)
	}

	log.Debugf("exchanging credentials for registry token at %s", realm)
	tokenResp, err := rc.client.Do(req)
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		return fmt.Errorf("token exchange returned %d: %s", tokenResp.StatusCode, string(body))
	}

	var tokenResult struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenResult); err != nil {
		return fmt.Errorf("could not decode token response: %w", err)
	}

	rc.token = tokenResult.Token
	if rc.token == "" {
		rc.token = tokenResult.AccessToken
	}
	if rc.token == "" {
		return fmt.Errorf("no token returned from registry auth endpoint")
	}

	return nil
}

func (rc *registryClient) fetchBlob(digest string) (io.ReadCloser, error) {
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", rc.registry, rc.repo, digest)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if rc.token != "" {
		req.Header.Set("Authorization", "Bearer "+rc.token)
	}

	log.Debugf("fetching blob %s from registry", digest)
	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not fetch blob %s: %w", digest, err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("registry returned %d for blob %s", resp.StatusCode, digest)
	}

	return resp.Body, nil
}

func parseWWWAuthenticate(header string) (realm, service string, err error) {
	if !strings.HasPrefix(header, "Bearer ") {
		return "", "", fmt.Errorf("unsupported auth scheme in %q", header)
	}

	params := header[7:]
	for _, part := range strings.Split(params, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		val := strings.Trim(kv[1], `"`)
		switch kv[0] {
		case "realm":
			realm = val
		case "service":
			service = val
		}
	}

	if realm == "" {
		return "", "", fmt.Errorf("no realm in WWW-Authenticate header: %q", header)
	}

	return realm, service, nil
}

func blobPathToDigest(blobPath string) string {
	parts := strings.Split(blobPath, "/")
	if len(parts) >= 3 && parts[0] == "blobs" {
		return parts[1] + ":" + strings.Join(parts[2:], "/")
	}
	return blobPath
}
