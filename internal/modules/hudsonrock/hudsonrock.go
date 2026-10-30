package hudsonrock

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

type hudsonRockClient struct {
	fileWriter *file.FileWriter
	out        io.Writer
	httpClient *http.Client
}

type hudsonRockResponse struct {
	Message  string    `json:"message"`
	Stealers []stealer `json:"stealers"`
}

type stealer struct {
	TotalCorporateServices int      `json:"total_corporate_services"`
	TotalUserServices      int      `json:"total_user_services"`
	DateCompromised        string   `json:"date_compromised"`
	StealerFamily          string   `json:"stealer_family"`
	ComputerName           string   `json:"computer_name"`
	OperatingSystem        string   `json:"operating_system"`
	MalwarePath            string   `json:"malware_path"`
	Antiviruses            any      `json:"antiviruses"`
	IP                     string   `json:"ip"`
	TopPasswords           []string `json:"top_passwords"`
	TopLogins              []string `json:"top_logins"`
}

func NewHudsonRockClient(out io.Writer, fileWriter *file.FileWriter) modules.Module {
	httpClient := config.NewHTTPClient()

	return &hudsonRockClient{
		fileWriter: fileWriter,
		out:        out,
		httpClient: httpClient,
	}
}

func (hrc *hudsonRockClient) Name() string {
	return "HudsonRock"
}

func (hrc *hudsonRockClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	theme.Cyanf("[*] Searching %s on HudsonRock...", query).Fprintln(hrc.out)

	response, err := hrc.buildRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(response.Stealers) == 0 {
		theme.Redf("[-] No HudsonRock profile found for %s", query).Fprintln(hrc.out)
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d info-stealer infection(s) for %s:", len(response.Stealers), query).Fprintln(hrc.out)
	fmt.Fprintf(&buffer, "[+] Found %d info-stealer infection(s) for %s:\n", len(response.Stealers), query)

	for index, entry := range response.Stealers {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		theme.Greenf(":: %03d :: %-18s : %s", index+1, "Stealer Family", entry.StealerFamily).Fprintln(hrc.out)
		theme.Greenf("          %-18s : %s", "Date Compromised", entry.DateCompromised).Fprintln(hrc.out)
		theme.Greenf("          %-18s : %s", "Computer Name", entry.ComputerName).Fprintln(hrc.out)
		theme.Greenf("          %-18s : %s", "Operating System", entry.OperatingSystem).Fprintln(hrc.out)
		theme.Greenf("          %-18s : %s", "IP", entry.IP).Fprintln(hrc.out)
		theme.Greenf("          %-18s : %s", "Malware Path", strings.TrimSpace(entry.MalwarePath)).Fprintln(hrc.out)
		theme.Greenf("          %-18s : %v", "Antiviruses", entry.Antiviruses).Fprintln(hrc.out)
		theme.Greenf("          %-18s : %d", "Corporate Services", entry.TotalCorporateServices).Fprintln(hrc.out)
		theme.Greenf("          %-18s : %d", "User Services", entry.TotalUserServices).Fprintln(hrc.out)
		theme.Greenf("          %-18s : %s", "Top Passwords", strings.Join(entry.TopPasswords, ", ")).Fprintln(hrc.out)
		theme.Greenf("          %-18s : %s", "Top Logins", strings.Join(entry.TopLogins, ", ")).Fprintln(hrc.out)

		fmt.Fprintf(&buffer, ":: %03d :: %-18s : %s\n", index+1, "Stealer Family", entry.StealerFamily)
		fmt.Fprintf(&buffer, "          %-18s : %s\n", "Date Compromised", entry.DateCompromised)
		fmt.Fprintf(&buffer, "          %-18s : %s\n", "Computer Name", entry.ComputerName)
		fmt.Fprintf(&buffer, "          %-18s : %s\n", "Operating System", entry.OperatingSystem)
		fmt.Fprintf(&buffer, "          %-18s : %s\n", "IP", entry.IP)
		fmt.Fprintf(&buffer, "          %-18s : %s\n", "Malware Path", strings.TrimSpace(entry.MalwarePath))
		fmt.Fprintf(&buffer, "          %-18s : %v\n", "Antiviruses", entry.Antiviruses)
		fmt.Fprintf(&buffer, "          %-18s : %d\n", "Corporate Services", entry.TotalCorporateServices)
		fmt.Fprintf(&buffer, "          %-18s : %d\n", "User Services", entry.TotalUserServices)
		fmt.Fprintf(&buffer, "          %-18s : %s\n", "Top Passwords", strings.Join(entry.TopPasswords, ", "))
		fmt.Fprintf(&buffer, "          %-18s : %s\n", "Top Logins", strings.Join(entry.TopLogins, ", "))
	}

	if err := hrc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(hrc.out)
	}

	result := modules.Result{
		Module:  hrc.Name(),
		Summary: fmt.Sprintf("%d infection(s) found", len(response.Stealers)),
	}

	return &result, nil
}

func (hrc *hudsonRockClient) buildRequest(ctx context.Context, query string) (*hudsonRockResponse, error) {
	endpoint := fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=%s", url.QueryEscape(query))

	response, err := modules.FetchJSON[hudsonRockResponse](ctx, hrc.httpClient, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildRequest): %w", hrc.Name(), err)
	}

	return response, nil
}
