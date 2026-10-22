package gravatar

import (
	"context"
	"encoding/json"
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

type gravatarClient struct {
	fileWriter *file.FileWriter
	httpClient *http.Client
}

var errGravatarUserNotFound = errors.New("gravatar: user not found")

type gravatarResponse struct {
	Entry []gravatarUser `json:"entry"`
}

type gravatarUser struct {
	EmailHash         string                 `json:"hash"`
	Username          string                 `json:"requestHash"`
	PreferredUsername string                 `json:"preferredUsername"`
	DisplayName       string                 `json:"displayName"`
	AboutMe           string                 `json:"aboutMe"`
	Emails            []gravatarUserEmails   `json:"emails"`
	Accounts          []gravatarUserAccounts `json:"accounts"`
}

type gravatarUserEmails struct {
	Email string `json:"value"`
}

type gravatarUserAccounts struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Name     string `json:"name"`
}

func NewGravatarClient(fileWriter *file.FileWriter) modules.Module {
	httpClient := config.NewHTTPClient()

	return &gravatarClient{
		fileWriter: fileWriter,
		httpClient: httpClient,
	}
}

func (gc *gravatarClient) Name() string {
	return "Gravatar"
}

func (gc *gravatarClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	theme.Cyanf("[*] Searching %s on Gravatar...", query).Println()

	response, err := gc.buildRequest(ctx, query)
	if err != nil {
		if errors.Is(err, errGravatarUserNotFound) {
			theme.Redf("[-] No Gravatar profile found for %s", query).Println()
			return nil, nil
		}

		return nil, err
	}

	var buffer strings.Builder

	for index, entry := range response.Entry {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		theme.Greenf("[+] Gravatar username found: %s", entry.Username).Println()
		fmt.Fprintf(&buffer, "[+] Gravatar username found: %s\n", entry.Username)

		if entry.DisplayName != "" {
			theme.Greenf(":: %03d :: %-18s : %s", index+1, "Display name", entry.DisplayName).Println()
			fmt.Fprintf(&buffer, ":: %03d :: %-18s : %s\n", index+1, "Display name", entry.DisplayName)
		}

		if entry.PreferredUsername != "" && entry.Username != entry.PreferredUsername {
			theme.Greenf("          %-18s : %s", "Preferred username", entry.PreferredUsername).Println()
			fmt.Fprintf(&buffer, "          %-18s : %s\n", "Preferred username", entry.PreferredUsername)
		}

		if entry.AboutMe != "" {
			theme.Greenf("          %-18s : %s", "About Me", entry.AboutMe).Println()
			fmt.Fprintf(&buffer, "          %-18s : %s\n", "About Me", entry.AboutMe)
		}

		if len(entry.Emails) == 0 {
			theme.Greenf("          %-18s : %s", "SHA256 Email Hash", entry.EmailHash).Println()
			theme.Green("          Hashcat command to crack this hash:").Println()
			theme.Greenf("          hashcat -m 1400 -a 0 %s facebook-firstnames.txt -r rules/MISC/emails-combined.rule --bitmap-max 28", entry.EmailHash).Println()
			theme.Green("          Hashcat rules can be found @ https://github.com/ibnaleem/rules").Println()
			theme.Green("          Wordlists can be found @ https://weakpass.com/wordlists?name=name").Println()
			theme.Green("          You could also submit this hash to Hashmob.net if you cannot crack it").Println()

			fmt.Fprintf(&buffer, "          %-18s : %s\n", "SHA256 Email Hash", entry.EmailHash)
			fmt.Fprintf(&buffer, "          Hashcat command to crack this hash:\n")
			fmt.Fprintf(&buffer, "          hashcat -m 1400 -a 0 %s facebook-firstnames.txt -r rules/MISC/emails-combined.rule --bitmap-max 28\n", entry.EmailHash)
			fmt.Fprintf(&buffer, "          Hashcat rules can be found @ https://github.com/ibnaleem/rules\n")
			fmt.Fprintf(&buffer, "          Wordlists can be found @ https://weakpass.com/wordlists?name=name\n")
			fmt.Fprintf(&buffer, "          You could also submit this hash to Hashmob.net if you cannot crack it\n")
		}

		if len(entry.Emails) > 0 {
			theme.Greenf("[+] Email(s) found for %s:", entry.Username).Println()
			fmt.Fprintf(&buffer, "[+] Email(s) found for %s:\n", entry.Username)
			for _, email := range entry.Emails {
				theme.Greenf("          %s", email.Email).Println()
				fmt.Fprintf(&buffer, "          %s\n", email.Email)
			}
		}

		if len(entry.Accounts) == 0 {
			continue
		}

		theme.Greenf("[+] Account(s) found for %s:", entry.Username).Println()
		fmt.Fprintf(&buffer, "[+] Account(s) found for %s:\n", entry.Username)
		for _, account := range entry.Accounts {
			theme.Greenf("          %-11s : %s", "Platform", account.Name).Println()
			theme.Greenf("          %-11s : %s", "Account URL", account.URL).Println()
			theme.Greenf("          %-11s : %s", "Username", account.Username).Println()

			fmt.Fprintf(&buffer, "          %-11s : %s\n", "Platform", account.Name)
			fmt.Fprintf(&buffer, "          %-11s : %s\n", "Account URL", account.URL)
			fmt.Fprintf(&buffer, "          %-11s : %s\n", "Username", account.Username)
		}
	}

	if err := gc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	result := modules.Result{
		Module:  gc.Name(),
		Summary: fmt.Sprintf("%d profile(s) found", len(response.Entry)),
	}

	return &result, nil
}

func (gc *gravatarClient) buildRequest(ctx context.Context, query string) (*gravatarResponse, error) {
	// The username comes from user input and becomes a path segment, so it is
	// path-escaped: unescaped, "foo#bar" or "foo?bar" would cut the path short
	// at the fragment/query, "a/b" would request a different path, and "100%"
	// would fail to parse as a URL at all.
	endpoint := fmt.Sprintf("https://gravatar.com/%s.json", url.PathEscape(query))

	// A missing user comes back as the JSON string "User not found" rather than
	// an object, so the body is fetched raw and checked before decoding.
	body, err := modules.FetchJSON[json.RawMessage](ctx, gc.httpClient, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildRequest): %w", gc.Name(), err)
	}

	if strings.TrimSpace(string(*body)) == `"User not found"` {
		return nil, errGravatarUserNotFound
	}

	var gravatarResponse gravatarResponse
	if err := json.Unmarshal(*body, &gravatarResponse); err != nil {
		return nil, fmt.Errorf("%s(buildRequest): decode response: %w", gc.Name(), err)
	}

	return &gravatarResponse, nil
}
