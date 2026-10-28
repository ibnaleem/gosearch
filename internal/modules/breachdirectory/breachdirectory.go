package breachdirectory

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/file"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/theme"
)

// hashCracker turns a password hash into plaintext. main.go passes in a
// weakpass.HashCracker, so this module doesn't depend on Weakpass directly.
type hashCracker interface {
	CrackHash(ctx context.Context, hash string) (string, error)
}

type breachDirectoryClient struct {
	fileWriter *file.FileWriter
	httpClient *http.Client
	cracker    hashCracker
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

func NewBreachDirectoryClient(fileWriter *file.FileWriter, cracker hashCracker, apiKey string) modules.Module {
	httpClient := config.NewHTTPClient()

	return &breachDirectoryClient{
		fileWriter: fileWriter,
		httpClient: httpClient,
		cracker:    cracker,
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

		cracked, err := bdc.cracker.CrackHash(ctx, entry.Sha1)
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

func (bdc *breachDirectoryClient) buildRequest(ctx context.Context, query string) (*breachDirectoryResponse, error) {
	endpoint := fmt.Sprintf("https://breachdirectory.p.rapidapi.com/?func=auto&term=%s", url.QueryEscape(query))

	headers := map[string]string{
		"x-rapidapi-key":  bdc.apiKey,
		"x-rapidapi-host": "breachdirectory.p.rapidapi.com",
	}

	response, err := modules.FetchJSON[breachDirectoryResponse](ctx, bdc.httpClient, endpoint, headers)
	if err != nil {
		return nil, fmt.Errorf("%s(buildRequest): %w", bdc.Name(), err)
	}

	return response, nil
}
