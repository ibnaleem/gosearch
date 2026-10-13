package breachdirectory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/file"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/theme"
)

type breachDirectoryClient struct {
	fileWriter *file.FileWriter
	httpClient *http.Client
	apiKey     string
}

type breachDirectoryResponse struct {
	Found  int           `json:"found"`
	Result []breachEntry `json:"result"`
}

type breachEntry struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Sha1     string `json:"sha1"`
	Hash     string `json:"hash"`
	Sources  string `json:"sources"`
}

type weakpassResponse struct {
	Type string `json:"type"`
	Hash string `json:"hash"`
	Pass string `json:"pass"`
}

func NewBreachDirectoryClient(fileWriter *file.FileWriter, apiKey string) modules.Module {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: config.TLSConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	return &breachDirectoryClient{
		fileWriter: fileWriter,
		httpClient: httpClient,
		apiKey:     apiKey,
	}
}

func (bdc *breachDirectoryClient) Name() string {
	return "BreachDirectory"
}

func (bdc *breachDirectoryClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	if query == "" {
		return nil, errors.New("empty search query")
	}

	if bdc.apiKey == "" {
		theme.Yellow("[!] Skipping Breach Directory: no API key provided (use -bd <key>).").Println()
		return nil, nil
	}

	theme.Cyan("[*] Searching ", query, " on Breach Directory for any compromised passwords...").Println()
	response, err := bdc.buildRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if response.Found == 0 {
		theme.Redf("[-] No breaches found for %s.", query).Println()
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d breach(es) for %s:", response.Found, query).Println()
	fmt.Fprintf(&buffer, "[+] Found %d breach(es) for %s:\n", response.Found, query)

	for index, entry := range response.Result {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		cracked, err := bdc.crackHashViaWeakpass(ctx, entry.Sha1)
		if err != nil {
			theme.Yellowf("[!] Could not crack hash: %v", err).Println()
		}

		password := entry.Password
		if err == nil && cracked != "" {
			password = cracked
		}

		theme.Greenf(":: %03d :: %-9s %s", index+1, "Password:", password).Println()
		theme.Greenf("          %-9s %s", "SHA1:", entry.Sha1).Println()
		theme.Greenf("          %-9s %s", "Source:", entry.Sources).Println()

		fmt.Fprintf(&buffer, ":: %03d :: %-9s %s\n", index+1, "Password:", password)
		fmt.Fprintf(&buffer, "          %-9s %s\n", "SHA1:", entry.Sha1)
		fmt.Fprintf(&buffer, "          %-9s %s\n", "Source:", entry.Sources)
	}

	if err := bdc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	result := modules.Result{
		Module:  bdc.Name(),
		Summary: fmt.Sprintf("%d breach(es) found", response.Found),
	}

	return &result, nil
}

func (bdc *breachDirectoryClient) buildRequest(ctx context.Context, param any) (*breachDirectoryResponse, error) {
	endpoint := fmt.Sprintf("https://breachdirectory.p.rapidapi.com/?func=auto&term=%s", url.QueryEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildRequest): create request: %w", bdc.Name(), err)
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/json")

	request.Header.Set("x-rapidapi-key", bdc.apiKey)
	request.Header.Set("x-rapidapi-host", "breachdirectory.p.rapidapi.com")

	response, err := bdc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildRequest): send request: %w", bdc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(bdc.Name(), "buildRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildRequest): read response: %w", bdc.Name(), err)
	}

	var breachDirectoryResponse breachDirectoryResponse
	if err = json.Unmarshal(body, &breachDirectoryResponse); err != nil {
		return nil, fmt.Errorf("%s(buildRequest): decode response: %w", bdc.Name(), err)
	}

	return &breachDirectoryResponse, nil
}

func (bdc *breachDirectoryClient) crackHashViaWeakpass(ctx context.Context, hash string) (string, error) {
	if hash == "" {
		return "", nil
	}

	endpoint := fmt.Sprintf("https://weakpass.com/api/v1/search/%s.json", url.PathEscape(hash))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("%s(crackHashViaWeakpass): build request: %w", bdc.Name(), err)
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/json")

	response, err := bdc.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("%s(crackHashViaWeakpass): send request: %w", bdc.Name(), err)
	}

	defer response.Body.Close()

	switch {
	case response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound:
		// 403 (rate limited) and 404 (hash not in Weakpass) just mean "not cracked".
		return "", nil
	case response.StatusCode < 200 || response.StatusCode >= 300:
		return "", fmt.Errorf("%s(crackHashViaWeakpass): unexpected status %d", bdc.Name(), response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("%s(crackHashViaWeakpass): read response: %w", bdc.Name(), err)
	}

	var weakpassResponse weakpassResponse
	if err := json.Unmarshal(body, &weakpassResponse); err != nil {
		return "", fmt.Errorf("%s(crackHashViaWeakpass): decode response: %w", bdc.Name(), err)
	}

	return weakpassResponse.Pass, nil
}
