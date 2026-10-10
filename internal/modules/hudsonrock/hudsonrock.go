package hudsonrock

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

type hudsonRockClient struct {
	fileWriter *file.FileWriter
	httpClient *http.Client
}

func NewHudsonRockClient(fileWriter *file.FileWriter) modules.Module {
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

	return &hudsonRockClient{
		fileWriter: fileWriter,
		httpClient: httpClient,
	}
}

func (x *hudsonRockClient) Name() string {
	return "HudsonRock"
}

func (x *hudsonRockClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	theme.Cyanf("[*] Searching %s on HudsonRock...", query).Println()

	response, err := x.buildRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(response.Stealers) == 0 {
		theme.Redf("[-] No HudsonRock profile found for %s", query).Println()
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d info-stealer infection(s) for %s:", len(response.Stealers), query).Println()
	fmt.Fprintf(&buffer, "[+] Found %d info-stealer infection(s) for %s:\n", len(response.Stealers), query)

	for index, entry := range response.Stealers {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		theme.Greenf(":: %03d :: %-18s : %s", index+1, "Stealer Family", entry.StealerFamily).Println()
		theme.Greenf("          %-18s : %s", "Date Compromised", entry.DateCompromised).Println()
		theme.Greenf("          %-18s : %s", "Computer Name", entry.ComputerName).Println()
		theme.Greenf("          %-18s : %s", "Operating System", entry.OperatingSystem).Println()
		theme.Greenf("          %-18s : %s", "IP", entry.IP).Println()
		theme.Greenf("          %-18s : %s", "Malware Path", strings.TrimSpace(entry.MalwarePath)).Println()
		theme.Greenf("          %-18s : %v", "Antiviruses", entry.Antiviruses).Println()
		theme.Greenf("          %-18s : %d", "Corporate Services", entry.TotalCorporateServices).Println()
		theme.Greenf("          %-18s : %d", "User Services", entry.TotalUserServices).Println()
		theme.Greenf("          %-18s : %s", "Top Passwords", strings.Join(entry.TopPasswords, ", ")).Println()
		theme.Greenf("          %-18s : %s", "Top Logins", strings.Join(entry.TopLogins, ", ")).Println()

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

	if err := x.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	result := modules.Result{
		Module:  x.Name(),
		Summary: fmt.Sprintf("%d infection(s) found", len(response.Stealers)),
	}

	return &result, nil
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

func (x *hudsonRockClient) buildRequest(ctx context.Context, param any) (*hudsonRockResponse, error) {
	endpoint := fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=%s", url.QueryEscape(fmt.Sprint(param)))

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

	var hudsonRockResponse hudsonRockResponse
	if err := json.Unmarshal(body, &hudsonRockResponse); err != nil {
		return nil, fmt.Errorf("%s(buildRequest): decode response: %w", x.Name(), err)
	}

	return &hudsonRockResponse, nil
}
