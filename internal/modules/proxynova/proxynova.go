package proxynova

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/file"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/theme"
)

type proxyNovaClient struct {
	fileWriter *file.FileWriter
	out        io.Writer
	httpClient *http.Client
}

type proxyNovaResponse struct {
	Count int      `json:"count"`
	Lines []string `json:"lines"`
}

func NewProxyNovaClient(out io.Writer, fileWriter *file.FileWriter) modules.Module {
	httpClient := config.NewHTTPClient()

	return &proxyNovaClient{
		fileWriter: fileWriter,
		out:        out,
		httpClient: httpClient,
	}
}

func (pnc *proxyNovaClient) Name() string {
	return "ProxyNova"
}

func (pnc *proxyNovaClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	theme.Cyan("[*] Searching ", query, " on ProxyNova for any compromised passwords...").Fprintln(pnc.out)
	response, err := pnc.buildRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if response.Count == 0 {
		theme.Red("[-] No compromised passwords found for ", query, ".").Fprintln(pnc.out)
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d compromised passwords for %s (showing %d):", response.Count, query, len(response.Lines)).Fprintln(pnc.out)
	fmt.Fprintf(&buffer, "[+] Found %d compromised passwords for %s (showing %d):\n", response.Count, query, len(response.Lines))

	for index, entry := range response.Lines {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			continue
		}

		theme.Greenf(":: %03d :: %-8s : %s", index+1, "Email", parts[0]).Fprintln(pnc.out)
		theme.Greenf("          %-8s : %s", "Password", parts[1]).Fprintln(pnc.out)

		fmt.Fprintf(&buffer, ":: %03d :: %-8s : %s\n", index+1, "Email", parts[0])
		fmt.Fprintf(&buffer, "          %-8s : %s\n", "Password", parts[1])
	}

	if err := pnc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(pnc.out)
	}

	result := modules.Result{
		Module:  pnc.Name(),
		Summary: fmt.Sprintf("%d compromised password(s) found", response.Count),
	}

	return &result, nil
}

func (pnc *proxyNovaClient) buildRequest(ctx context.Context, query string) (*proxyNovaResponse, error) {
	endpoint := fmt.Sprintf("https://api.proxynova.com/comb?query=%s", url.QueryEscape(query))

	response, err := modules.FetchJSON[proxyNovaResponse](ctx, pnc.httpClient, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildRequest): %w", pnc.Name(), err)
	}

	return response, nil
}
