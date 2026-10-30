package keybase

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/file"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/theme"
)

type keyBaseClient struct {
	fileWriter *file.FileWriter
	out        io.Writer
	httpClient *http.Client
}

type keyBaseResponse struct {
	Status keyBaseStatus `json:"status"`
	Users  []keyBaseUser `json:"them"`
}

type keyBaseStatus struct {
	Code int    `json:"code"`
	Name string `json:"name"`
}

type keyBaseUser struct {
	ID                      string                      `json:"id"`
	Basics                  keyBaseBasics               `json:"basics"`
	Profile                 keyBaseProfile              `json:"profile"`
	Pictures                keyBasePictures             `json:"pictures"`
	Stellar                 keyBaseStellar              `json:"stellar"`
	Devices                 map[string]keyBaseDevice    `json:"devices"`
	CryptocurrencyAddresses map[string][]keyBaseAddress `json:"cryptocurrency_addresses"`
	ProofsSummary           keyBaseProofsSummary        `json:"proofs_summary"`
}

type keyBaseBasics struct {
	Username      string `json:"username"`
	Ctime         int64  `json:"ctime"`
	Mtime         int64  `json:"mtime"`
	UsernameCased string `json:"username_cased"`
}

type keyBaseProfile struct {
	FullName string `json:"full_name"`
	Location string `json:"location"`
	Bio      string `json:"bio"`
}

type keyBasePictures struct {
	Primary *keyBasePicture `json:"primary"`
}

type keyBasePicture struct {
	URL string `json:"url"`
}

type keyBaseStellar struct {
	Hidden  bool                   `json:"hidden"`
	Primary *keyBaseStellarAccount `json:"primary"`
}

type keyBaseStellarAccount struct {
	AccountID string `json:"account_id"`
}

type keyBaseDevice struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type keyBaseAddress struct {
	Address string `json:"address"`
}

type keyBaseProofsSummary struct {
	All []keyBaseProof `json:"all"`
}

type keyBaseProof struct {
	ProofType  string `json:"proof_type"`
	Nametag    string `json:"nametag"`
	ServiceURL string `json:"service_url"`
}

func NewKeyBaseClient(out io.Writer, fileWriter *file.FileWriter) modules.Module {
	httpClient := config.NewHTTPClient()

	return &keyBaseClient{
		fileWriter: fileWriter,
		out:        out,
		httpClient: httpClient,
	}
}

func (kbc *keyBaseClient) Name() string {
	return "KeyBase"
}

func (kbc *keyBaseClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	theme.Cyanf("[*] Searching %s on Keybase...", query).Fprintln(kbc.out)
	response, err := kbc.buildRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(response.Users) == 0 {
		theme.Red("[-] No Keybase profile found for ", query).Fprintln(kbc.out)
		return nil, nil
	}

	var buffer strings.Builder

	for index, entry := range response.Users {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		if entry.ID == "" && entry.Basics.Username == "" {
			theme.Red("[-] No Keybase profile found for ", query).Fprintln(kbc.out)
			return nil, nil
		}

		theme.Greenf("[+] Keybase username found: %s", query).Fprintln(kbc.out)
		fmt.Fprintf(&buffer, "[+] Keybase username found: %s\n", query)

		if entry.ID != "" {
			theme.Greenf(":: %03d :: %-16s : %s", index+1, "User ID", entry.ID).Fprintln(kbc.out)
			fmt.Fprintf(&buffer, ":: %03d :: %-16s : %s\n", index+1, "User ID", entry.ID)
		}

		if entry.Basics.UsernameCased != "" && entry.Basics.UsernameCased != query {
			theme.Greenf("          %-16s : %s", "Username", entry.Basics.UsernameCased).Fprintln(kbc.out)
			fmt.Fprintf(&buffer, "          %-16s : %s\n", "Username", entry.Basics.UsernameCased)
		}

		if entry.Basics.Ctime != 0 {
			theme.Greenf("          %-16s : %s", "Created at", time.Unix(entry.Basics.Ctime, 0).UTC().Format(time.RFC3339)).Fprintln(kbc.out)
			fmt.Fprintf(&buffer, "          %-16s : %s\n", "Created at", time.Unix(entry.Basics.Ctime, 0).UTC().Format(time.RFC3339))
		}

		if entry.Basics.Mtime != 0 {
			theme.Greenf("          %-16s : %s", "Updated at", time.Unix(entry.Basics.Mtime, 0).UTC().Format(time.RFC3339)).Fprintln(kbc.out)
			fmt.Fprintf(&buffer, "          %-16s : %s\n", "Updated at", time.Unix(entry.Basics.Mtime, 0).UTC().Format(time.RFC3339))
		}

		if entry.Profile.FullName != "" {
			theme.Greenf("          %-16s : %s", "Name", entry.Profile.FullName).Fprintln(kbc.out)
			fmt.Fprintf(&buffer, "          %-16s : %s\n", "Name", entry.Profile.FullName)
		}

		if entry.Profile.Location != "" {
			theme.Greenf("          %-16s : %s", "Current location", entry.Profile.Location).Fprintln(kbc.out)
			fmt.Fprintf(&buffer, "          %-16s : %s\n", "Current location", entry.Profile.Location)
		}

		if entry.Profile.Bio != "" {
			theme.Greenf("          %-16s : %s", "Bio", entry.Profile.Bio).Fprintln(kbc.out)
			fmt.Fprintf(&buffer, "          %-16s : %s\n", "Bio", entry.Profile.Bio)
		}

		if entry.Pictures.Primary != nil && entry.Pictures.Primary.URL != "" {
			theme.Greenf("          %-16s : %s", "Avatar URL", entry.Pictures.Primary.URL).Fprintln(kbc.out)
			fmt.Fprintf(&buffer, "          %-16s : %s\n", "Avatar URL", entry.Pictures.Primary.URL)
		}

		if entry.Stellar.Primary != nil && entry.Stellar.Primary.AccountID != "" {
			theme.Greenf("          %-16s : %s", "Stellar account", entry.Stellar.Primary.AccountID).Fprintln(kbc.out)
			fmt.Fprintf(&buffer, "          %-16s : %s\n", "Stellar account", entry.Stellar.Primary.AccountID)
		}

		if len(entry.ProofsSummary.All) > 0 {
			theme.Greenf("[+] Identity proof(s) was found for %s:", query).Fprintln(kbc.out)
			fmt.Fprintf(&buffer, "[+] Identity proof(s) was found for %s:\n", query)
			for _, entry := range entry.ProofsSummary.All {
				if entry.ServiceURL != "" {
					theme.Greenf("          %-10s : %s (%s)", entry.ProofType, entry.Nametag, entry.ServiceURL).Fprintln(kbc.out)
					fmt.Fprintf(&buffer, "          %-10s : %s (%s)\n", entry.ProofType, entry.Nametag, entry.ServiceURL)
				} else {
					theme.Greenf("          %-10s : %s", entry.ProofType, entry.Nametag).Fprintln(kbc.out)
					fmt.Fprintf(&buffer, "          %-10s : %s\n", entry.ProofType, entry.Nametag)
				}
			}
		}

		if len(entry.CryptocurrencyAddresses) > 0 {
			theme.Green("[+] Cryptocurrency addresses:").Fprintln(kbc.out)
			fmt.Fprintf(&buffer, "[+] Cryptocurrency addresses:\n")
			for coin, addresses := range entry.CryptocurrencyAddresses {
				for _, address := range addresses {
					if address.Address != "" {
						theme.Greenf("          %-10s : %s", coin, address.Address).Fprintln(kbc.out)
						fmt.Fprintf(&buffer, "          %-10s : %s\n", coin, address.Address)
					}
				}
			}
		}

		if len(entry.Devices) > 0 {
			theme.Greenf("[+] Device(s) found for %s:", query).Fprintln(kbc.out)
			fmt.Fprintf(&buffer, "[+] Device(s) found for %s:\n", query)

			devices := make([]keyBaseDevice, 0, len(entry.Devices))
			for _, device := range entry.Devices {
				devices = append(devices, device)
			}

			sort.Slice(devices, func(i, j int) bool {
				if devices[i].Type != devices[j].Type {
					return devices[i].Type < devices[j].Type
				}

				return devices[i].Name < devices[j].Name
			})

			for _, device := range devices {
				theme.Greenf("          %-10s : %s", device.Type, device.Name).Fprintln(kbc.out)
				fmt.Fprintf(&buffer, "          %-10s : %s\n", device.Type, device.Name)
			}
		}
	}

	if err := kbc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(kbc.out)
	}

	result := modules.Result{
		Module:  kbc.Name(),
		Summary: fmt.Sprintf("%d profile(s) found", len(response.Users)),
	}

	return &result, nil
}

func (kbc *keyBaseClient) buildRequest(ctx context.Context, query string) (*keyBaseResponse, error) {
	endpoint := fmt.Sprintf("https://keybase.io/_/api/1.0/user/lookup.json?usernames=%s", url.QueryEscape(query))

	response, err := modules.FetchJSON[keyBaseResponse](ctx, kbc.httpClient, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildRequest): %w", kbc.Name(), err)
	}

	switch response.Status.Code {
	case 0:
	case 100: // INPUT_ERROR: a name Keybase can't have, e.g. with "." or over 16 characters
		return &keyBaseResponse{}, nil
	default:
		return nil, fmt.Errorf("%s(buildRequest): api status %d (%s)", kbc.Name(), response.Status.Code, response.Status.Name)
	}

	return response, nil
}
