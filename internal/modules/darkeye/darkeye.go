package darkeye

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/file"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/theme"
)

const (
	haveIBeenRansom = "HaveIBeenRansom"
	breachHouse     = "Breach House"
)

type darkEyeClient struct {
	fileWriter     *file.FileWriter
	out            io.Writer
	httpClient     *http.Client
	hibrKey        string
	breachHouseKey string
	hibrURL        string
	breachHouseURL string
}

// probe is one term to look up: the HaveIBeenRansom field to search it in
// ("username" or "email") and the term itself.
type probe struct {
	field string
	term  string
}

// lookup is what one term found in one product.
type lookup struct {
	records   []record
	truncated bool
}

func NewDarkEyeClient(out io.Writer, fileWriter *file.FileWriter, hibrKey, breachHouseKey string) modules.Module {
	httpClient := config.NewHTTPClient()

	// the API keys go out in an Authorization header, so a redirect is an
	// error instead of a second request to wherever it points
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("refusing to follow a redirect")
	}

	return &darkEyeClient{
		fileWriter:     fileWriter,
		out:            out,
		httpClient:     httpClient,
		hibrKey:        strings.TrimSpace(hibrKey),
		breachHouseKey: strings.TrimSpace(breachHouseKey),
		hibrURL:        "https://haveibeenransom.com/api/metadata",
		breachHouseURL: "https://breach.house/api/v1/search",
	}
}

func (dec *darkEyeClient) Name() string {
	return "DarkEye"
}

// Search looks the username up in HaveIBeenRansom, then looks up the common
// email addresses built from it in HaveIBeenRansom and Breach House. A
// username with "-" is only looked up through its emails. Breach
// House is free text search, so a bare username would only return companies
// and it is never sent one. A product without its API key is skipped, and
// one product failing doesn't discard what the other found.
func (dec *darkEyeClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	if query == "" {
		return nil, errors.New("empty search query")
	}

	if dec.hibrKey == "" {
		theme.Yellow("[*] DARKEYE_HIBR_API_KEY not set, skipping ", haveIBeenRansom, ".").Fprintln(dec.out)
	}

	if dec.breachHouseKey == "" {
		theme.Yellow("[*] DARKEYE_BREACHHOUSE_API_KEY not set, skipping ", breachHouse, ".").Fprintln(dec.out)
	}

	if dec.hibrKey == "" && dec.breachHouseKey == "" {
		return nil, nil
	}

	emails := commonEmails(query)

	if len(emails) > 0 {
		fmt.Fprintln(dec.out, config.SEPERATOR)
		theme.Cyan("[*] Generated common email addresses for ", query, ":").Fprintln(dec.out)
		for _, email := range emails {
			theme.Greenf(":: %s", email).Fprintln(dec.out)
		}
	}

	var (
		total    int
		queried  int
		failures []string
	)

	if dec.hibrKey != "" {
		var probes []probe

		// HaveIBeenRansom's username search splits a term at "-" and also
		// matches listings that hold only part of it, so a hyphenated
		// username is only looked up through its emails, which are matched
		// whole.
		if strings.Contains(query, "-") {
			theme.Yellow("[*] ", query, " contains \"-\", so ", haveIBeenRansom, " is only searched with its email addresses.").Fprintln(dec.out)
		} else {
			probes = append(probes, probe{field: "username", term: query})
		}

		for _, email := range emails {
			probes = append(probes, probe{field: "email", term: email})
		}

		if len(probes) > 0 {
			queried++

			found, err := dec.run(ctx, haveIBeenRansom, query, probes, dec.searchHaveIBeenRansom)
			total += found
			if err != nil {
				failures = append(failures, err.Error())
			}
		}
	}

	if dec.breachHouseKey != "" {
		switch {
		case len(emails) == 0:
			theme.Yellow("[*] ", breachHouse, " is only searched with email addresses and none can be built from ", query, ", skipping.").Fprintln(dec.out)

		default:
			probes := make([]probe, 0, len(emails))
			for _, email := range emails {
				probes = append(probes, probe{field: "email", term: email})
			}

			queried++

			found, err := dec.run(ctx, breachHouse, query, probes, dec.searchBreachHouse)
			total += found
			if err != nil {
				failures = append(failures, err.Error())
			}
		}
	}

	if queried == 0 {
		return nil, nil
	}

	// a failed lookup is never reported as "nothing found"
	if len(failures) == queried && total == 0 {
		return nil, fmt.Errorf("%s(Search): every lookup failed: %s", dec.Name(), strings.Join(failures, "; "))
	}

	if total == 0 && len(failures) == 0 {
		theme.Redf("[-] No DarkEye records found for %s.", query).Fprintln(dec.out)
		return nil, nil
	}

	summary := fmt.Sprintf("%d record(s) found", total)
	if len(failures) > 0 {
		summary += fmt.Sprintf(", %d of %d product(s) failed", len(failures), queried)
	}

	return &modules.Result{
		Module:  dec.Name(),
		Summary: summary,
	}, nil
}

// run looks every probe up in one product and files its output under fileKey,
// so every term in a run lands in one report file. It stops at the first
// failure, because a rejected key or a rate limit fails every request after
// it too, and returns the number of records found before that. Records a
// failed lookup had already read (earlier pages) are still printed and
// filed, marked as incomplete.
func (dec *darkEyeClient) run(ctx context.Context, product, fileKey string, probes []probe, search func(context.Context, probe) (lookup, error)) (int, error) {
	total := 0

	for _, p := range probes {
		if ctxErr := ctx.Err(); ctxErr != nil {
			theme.Redf("[!] %s lookup stopped: %v", product, ctxErr).Fprintln(dec.out)
			return total, fmt.Errorf("%s(run): %w", dec.Name(), ctxErr)
		}

		theme.Cyan("[*] Searching ", p.term, " on ", product, " for any records...").Fprintln(dec.out)

		found, err := search(ctx, p)
		if err != nil {
			theme.Redf("[!] %s lookup failed for %s: %v", product, p.term, err).Fprintln(dec.out)
			total += dec.report(product, fileKey, p, found, true)
			return total, err
		}

		if len(found.records) == 0 {
			theme.Redf("[-] No %s records found for %s.", product, p.term).Fprintln(dec.out)
			if found.truncated {
				theme.Yellowf("[!] %s has more results for %s than were checked.", product, p.term).Fprintln(dec.out)
			}
			continue
		}

		total += dec.report(product, fileKey, p, found, false)
	}

	return total, nil
}

// report prints and files the records one lookup found and returns how many
// there were. failed marks a lookup that stopped partway, so its records are
// not taken for the full answer.
func (dec *darkEyeClient) report(product, fileKey string, p probe, found lookup, failed bool) int {
	if len(found.records) == 0 {
		return 0
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d %s record(s) for %s:", len(found.records), product, p.term).Fprintln(dec.out)
	fmt.Fprintf(&buffer, "[+] Found %d %s record(s) for %s:\n", len(found.records), product, p.term)

	for index, rec := range found.records {
		dec.writeRecord(&buffer, index+1, rec)
	}

	switch {
	case failed:
		theme.Yellowf("[!] The %s lookup for %s failed partway, so these records are incomplete.", product, p.term).Fprintln(dec.out)
		fmt.Fprintf(&buffer, "[!] The %s lookup for %s failed partway, so these records are incomplete.\n", product, p.term)
	case found.truncated:
		theme.Yellowf("[!] %s has more records for %s than are shown here.", product, p.term).Fprintln(dec.out)
		fmt.Fprintf(&buffer, "[!] %s has more records for %s than are shown here.\n", product, p.term)
	}

	if err := dec.fileWriter.Write(fileKey, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(dec.out)
	}

	return len(found.records)
}

// bearer is the Authorization header both APIs expect.
func bearer(key string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + key}
}
