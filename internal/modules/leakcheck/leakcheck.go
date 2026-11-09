package leakcheck

import (
	"context"
	"errors"
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

type leakcheckClient struct {
	fileWriter *file.FileWriter
	out        io.Writer
	httpClient *http.Client
	apiKey     string
}

// publicResponse is the free Public API shape. It names where an identifier
// leaked and which categories of data were exposed, never the values.
type publicResponse struct {
	Success bool           `json:"success"`
	Found   int            `json:"found"`
	Fields  []string       `json:"fields"`
	Sources []publicSource `json:"sources"`
}

type publicSource struct {
	Name string `json:"name"`
	Date string `json:"date"`
}

func NewLeakcheckClient(out io.Writer, fileWriter *file.FileWriter, apiKey string) modules.Module {
	return &leakcheckClient{
		fileWriter: fileWriter,
		out:        out,
		httpClient: config.NewHTTPClient(),
		apiKey:     apiKey,
	}
}

func (lc *leakcheckClient) Name() string {
	return "LeakCheck"
}

func (lc *leakcheckClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	if query == "" {
		return nil, errors.New("empty search query")
	}

	return lc.searchPublic(ctx, query)
}

func (lc *leakcheckClient) searchPublic(ctx context.Context, query string) (*modules.Result, error) {
	theme.Cyan("[*] Searching ", query, " on LeakCheck (public API) for any leaks...").Fprintln(lc.out)

	endpoint := "https://leakcheck.io/api/public?check=" + url.QueryEscape(query)

	response, err := modules.FetchJSON[publicResponse](ctx, lc.httpClient, endpoint, nil)
	if err != nil {
		if errors.Is(err, modules.ErrNotFound) {
			theme.Redf("[-] No leaks found for %s.", query).Fprintln(lc.out)
			return nil, nil
		}
		return nil, fmt.Errorf("%s(searchPublic): %w", lc.Name(), err)
	}

	if !response.Success || response.Found == 0 {
		theme.Redf("[-] No leaks found for %s.", query).Fprintln(lc.out)
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d leak(s) for %s:", response.Found, query).Fprintln(lc.out)
	fmt.Fprintf(&buffer, "[+] Found %d leak(s) for %s:\n", response.Found, query)

	if len(response.Fields) > 0 {
		exposed := strings.Join(response.Fields, ", ")
		theme.Greenf("          %-9s %s", "Exposed:", exposed).Fprintln(lc.out)
		fmt.Fprintf(&buffer, "          %-9s %s\n", "Exposed:", exposed)
	}

	for index, source := range response.Sources {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		theme.Greenf(":: %03d :: %-9s %s (%s)", index+1, "Source:", source.Name, source.Date).Fprintln(lc.out)
		fmt.Fprintf(&buffer, ":: %03d :: %-9s %s (%s)\n", index+1, "Source:", source.Name, source.Date)
	}

	if err := lc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(lc.out)
	}

	return &modules.Result{
		Module:  lc.Name(),
		Summary: fmt.Sprintf("%d leak(s) found", response.Found),
	}, nil
}
