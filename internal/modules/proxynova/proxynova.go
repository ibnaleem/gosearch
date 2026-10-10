package proxynova

import (
	"context"
	"encoding/json"
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

type proxyNovaClient struct {
	fileWriter *file.FileWriter
	httpClient *http.Client
}

func NewProxyNovaClient(fileWriter *file.FileWriter) modules.Module {
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

	return &proxyNovaClient{
		fileWriter: fileWriter,
		httpClient: httpClient,
	}
}

func (x *proxyNovaClient) Name() string {
	return "ProxyNova"
}

func (x *proxyNovaClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	theme.Cyan("[*] Searching ", query, " on ProxyNova for any compromised passwords...").Println()
	response, err := x.buildRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if response.Count == 0 {
		theme.Red("[-] No compromised passwords found for ", query, ".").Println()
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d compromised passwords for %s:", len(response.Lines), query).Println()
	fmt.Fprintf(&buffer, "[+] Found %d compromised passwords for %s:\n", len(response.Lines), query)

	for index, entry := range response.Lines {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			continue
		}

		theme.Greenf(":: %03d :: %-8s : %s", index+1, "Email", parts[0]).Println()
		theme.Greenf("          %-8s : %s", "Password", parts[1]).Println()

		fmt.Fprintf(&buffer, ":: %03d :: %-8s : %s\n", index+1, "Email", parts[0])
		fmt.Fprintf(&buffer, "          %-8s : %s\n", "Password", parts[1])
	}

	if err := x.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	result := modules.Result{
		Module:  x.Name(),
		Summary: fmt.Sprintf("%d compromised password(s) found", response.Count),
	}

	return &result, nil
}

type proxyNovaResponse struct {
	Count int      `json:"count"`
	Lines []string `json:"lines"`
}

func (x *proxyNovaClient) buildRequest(ctx context.Context, param any) (*proxyNovaResponse, error) {
	endpoint := fmt.Sprintf("https://api.proxynova.com/comb?query=%s", url.QueryEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildRequest): create request: %w", x.Name(), err)
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/json")

	response, err := x.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildRequest): send request: %w", x.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(x.Name(), "buildRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildRequest): read response: %w", x.Name(), err)
	}

	var proxyNovaResponse proxyNovaResponse
	if err := json.Unmarshal(body, &proxyNovaResponse); err != nil {
		return nil, fmt.Errorf("%s(buildRequest): decode response: %w", x.Name(), err)
	}

	return &proxyNovaResponse, nil

}
