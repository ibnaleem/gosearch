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

// hashCracker turns a password hash into plaintext. main.go passes in a
// weakpass.HashCracker, so this module doesn't depend on Weakpass directly.
type hashCracker interface {
	CrackHash(ctx context.Context, hash string) (string, error)
}

type leakcheckClient struct {
	fileWriter *file.FileWriter
	out        io.Writer
	httpClient *http.Client
	cracker    hashCracker
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

// proResponse is the Pro API v2 shape: full breach records, one row per hit.
type proResponse struct {
	Success bool     `json:"success"`
	Found   int      `json:"found"`
	Quota   int      `json:"quota"`
	Result  []proRow `json:"result"`
}

type proRow struct {
	Email    string    `json:"email"`
	Username string    `json:"username"`
	Password string    `json:"password"`
	Fields   []string  `json:"fields"`
	Source   proSource `json:"source"`
}

type proSource struct {
	Name       string `json:"name"`
	BreachDate string `json:"breach_date"`
}

func NewLeakcheckClient(out io.Writer, fileWriter *file.FileWriter, cracker hashCracker, apiKey string) modules.Module {
	return &leakcheckClient{
		fileWriter: fileWriter,
		out:        out,
		httpClient: config.NewHTTPClient(),
		cracker:    cracker,
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

	if lc.apiKey == "" {
		theme.Yellow("[!] No LEAKCHECK_API_KEY set; defaulting to the free LeakCheck public API.").Fprintln(lc.out)
	}

	total, err := lc.lookup(ctx, query, query)
	if err != nil {
		return nil, err
	}

	emails := commonEmails(query)

	fmt.Fprintln(lc.out, config.SEPERATOR)
	theme.Cyan("[*] Generated common email addresses for ", query, ":").Fprintln(lc.out)
	for _, email := range emails {
		theme.Greenf(":: %s", email).Fprintln(lc.out)
	}

	for _, email := range emails {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		found, err := lc.lookup(ctx, email, query)
		if err != nil {
			return nil, err
		}

		total += found
	}

	return &modules.Result{
		Module:  lc.Name(),
		Summary: fmt.Sprintf("%d leak(s) found", total),
	}, nil
}

// lookup searches one term and files its output under fileKey, so every term in
// a run (the username and the emails derived from it) lands in one report file.
// It returns the number of leaks found. Pro when a key is set, public otherwise.
func (lc *leakcheckClient) lookup(ctx context.Context, term, fileKey string) (int, error) {
	if lc.apiKey != "" {
		return lc.searchPro(ctx, term, fileKey)
	}

	return lc.searchPublic(ctx, term, fileKey)
}

func (lc *leakcheckClient) searchPublic(ctx context.Context, term, fileKey string) (int, error) {
	theme.Cyan("[*] Searching ", term, " on LeakCheck (public API) for any leaks...").Fprintln(lc.out)

	endpoint := "https://leakcheck.io/api/public?check=" + url.QueryEscape(term)

	response, err := modules.FetchJSON[publicResponse](ctx, lc.httpClient, endpoint, nil)
	if err != nil {
		if errors.Is(err, modules.ErrNotFound) {
			theme.Redf("[-] No leaks found for %s.", term).Fprintln(lc.out)
			return 0, nil
		}
		return 0, fmt.Errorf("%s(searchPublic): %w", lc.Name(), err)
	}

	if !response.Success || response.Found == 0 {
		theme.Redf("[-] No leaks found for %s.", term).Fprintln(lc.out)
		return 0, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d leak(s) for %s:", response.Found, term).Fprintln(lc.out)
	fmt.Fprintf(&buffer, "[+] Found %d leak(s) for %s:\n", response.Found, term)

	if len(response.Fields) > 0 {
		exposed := strings.Join(response.Fields, ", ")
		theme.Greenf("          %-9s %s", "Exposed:", exposed).Fprintln(lc.out)
		fmt.Fprintf(&buffer, "          %-9s %s\n", "Exposed:", exposed)
	}

	for index, source := range response.Sources {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, ctxErr
		}

		theme.Greenf(":: %03d :: %-9s %s (%s)", index+1, "Source:", source.Name, source.Date).Fprintln(lc.out)
		fmt.Fprintf(&buffer, ":: %03d :: %-9s %s (%s)\n", index+1, "Source:", source.Name, source.Date)
	}

	if err := lc.fileWriter.Write(fileKey, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(lc.out)
	}

	return response.Found, nil
}

func (lc *leakcheckClient) searchPro(ctx context.Context, term, fileKey string) (int, error) {
	theme.Cyan("[*] Searching ", term, " on LeakCheck (Pro API) for any leaks...").Fprintln(lc.out)

	endpoint := "https://leakcheck.io/api/v2/query/" + url.PathEscape(term) + "?limit=100"
	headers := map[string]string{"X-API-Key": lc.apiKey}

	response, err := modules.FetchJSON[proResponse](ctx, lc.httpClient, endpoint, headers)
	if err != nil {
		if errors.Is(err, modules.ErrNotFound) {
			theme.Redf("[-] No leaks found for %s.", term).Fprintln(lc.out)
			return 0, nil
		}
		return 0, fmt.Errorf("%s(searchPro): %w", lc.Name(), err)
	}

	if !response.Success || response.Found == 0 {
		theme.Redf("[-] No leaks found for %s.", term).Fprintln(lc.out)
		return 0, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d leak(s) for %s:", response.Found, term).Fprintln(lc.out)
	fmt.Fprintf(&buffer, "[+] Found %d leak(s) for %s:\n", response.Found, term)

	for index, row := range response.Result {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, ctxErr
		}

		password := row.Password
		if looksHashed(password) {
			cracked, err := lc.cracker.CrackHash(ctx, password)
			if err != nil {
				theme.Yellowf("[!] Could not crack hash: %v", err).Fprintln(lc.out)
			} else if cracked != "" {
				password = cracked
			}
		}

		lc.writeProRow(&buffer, index+1, row, password)
	}

	if err := lc.fileWriter.Write(fileKey, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(lc.out)
	}

	return response.Found, nil
}

func (lc *leakcheckClient) writeProRow(buffer *strings.Builder, n int, row proRow, password string) {
	source := row.Source.Name
	if row.Source.BreachDate != "" {
		source = fmt.Sprintf("%s (%s)", row.Source.Name, row.Source.BreachDate)
	}

	theme.Greenf(":: %03d :: %-9s %s", n, "Source:", source).Fprintln(lc.out)
	fmt.Fprintf(buffer, ":: %03d :: %-9s %s\n", n, "Source:", source)

	line := func(label, value string) {
		if value == "" {
			return
		}
		theme.Greenf("          %-9s %s", label, value).Fprintln(lc.out)
		fmt.Fprintf(buffer, "          %-9s %s\n", label, value)
	}

	line("Email:", row.Email)
	line("Username:", row.Username)
	line("Password:", password)
	if len(row.Fields) > 0 {
		line("Fields:", strings.Join(row.Fields, ", "))
	}
}

// looksHashed reports whether s is a password hash rather than plaintext, so we
// only spend a crack attempt on values that could be one: a bcrypt/crypt string
// ($2a$, $1$, ...) or an even-length hex digest (md5/sha1/sha256).
func looksHashed(s string) bool {
	if strings.HasPrefix(s, "$") {
		return true
	}

	if len(s) < 32 || len(s)%2 != 0 {
		return false
	}

	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}

	return true
}
