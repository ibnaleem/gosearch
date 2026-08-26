package keybase

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/theme"
)

type KeybaseLookup struct {
	Status KeybaseStatus  `json:"status"`
	Them   []*KeybaseUser `json:"them"`
}

type KeybaseStatus struct {
	Code int    `json:"code"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type KeybaseUser struct {
	ID                      string                      `json:"id"`
	Basics                  KeybaseBasics               `json:"basics"`
	Profile                 KeybaseProfile              `json:"profile"`
	Pictures                KeybasePictures             `json:"pictures"`
	Stellar                 KeybaseStellar              `json:"stellar"`
	Devices                 map[string]KeybaseDevice    `json:"devices"`
	CryptocurrencyAddresses map[string][]KeybaseAddress `json:"cryptocurrency_addresses"`
	ProofsSummary           KeybaseProofsSummary        `json:"proofs_summary"`
}

type KeybaseBasics struct {
	Username      string `json:"username"`
	Ctime         int64  `json:"ctime"`
	Mtime         int64  `json:"mtime"`
	UsernameCased string `json:"username_cased"`
}

type KeybaseProfile struct {
	FullName string `json:"full_name"`
	Location string `json:"location"`
	Bio      string `json:"bio"`
}

type KeybasePictures struct {
	Primary *KeybasePicture `json:"primary"`
}

type KeybasePicture struct {
	URL string `json:"url"`
}

type KeybaseStellar struct {
	Hidden  bool                   `json:"hidden"`
	Primary *KeybaseStellarAccount `json:"primary"`
}

type KeybaseStellarAccount struct {
	AccountID string `json:"account_id"`
}

type KeybaseDevice struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type KeybaseAddress struct {
	Address string `json:"address"`
}

type KeybaseProofsSummary struct {
	All []KeybaseProof `json:"all"`
}

type KeybaseProof struct {
	ProofType  string `json:"proof_type"`
	Nametag    string `json:"nametag"`
	ServiceURL string `json:"service_url"`
}

func UnmarshalKeybaseUser(username string) (KeybaseUser, error) {
	client := &http.Client{}
	url := fmt.Sprintf("https://keybase.io/_/api/1.0/user/lookup.json?usernames=%s", username)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return KeybaseUser{}, fmt.Errorf("error creating request for user %s: %w", username, err)
	}
	req.Header.Set("User-Agent", config.DefaultUserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return KeybaseUser{}, fmt.Errorf("error fetching user %s: %w", username, err)
	}
	defer resp.Body.Close()

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return KeybaseUser{}, fmt.Errorf("error reading response body for user %s: %w", username, err)
	}

	var lookup KeybaseLookup
	if err = json.Unmarshal(jsonData, &lookup); err != nil {
		return KeybaseUser{}, fmt.Errorf("error unmarshalling response for user %s: %w", username, err)
	}

	if lookup.Status.Code != 0 {
		return KeybaseUser{}, nil
	}

	if len(lookup.Them) == 0 || lookup.Them[0] == nil {
		return KeybaseUser{}, nil
	}

	return *lookup.Them[0], nil
}

func DisplayKeybaseInfo(keybaseUser KeybaseUser, username string) {
	if keybaseUser.ID == "" && keybaseUser.Basics.Username == "" {
		theme.Red("[-] No Keybase profile found for ", username).Println()
		return
	}

	theme.Greenf("[+] Keybase username found: %s", username).Println()

	if keybaseUser.ID != "" {
		theme.Greenf("[+] ↳ User ID: %s", keybaseUser.ID).Println()
	}
	if keybaseUser.Basics.UsernameCased != "" && keybaseUser.Basics.UsernameCased != username {
		theme.Greenf("[+] ↳ Username: %s", keybaseUser.Basics.UsernameCased).Println()
	}
	if keybaseUser.Basics.Ctime != 0 {
		theme.Greenf("[+] ↳ Created at: %s", time.Unix(keybaseUser.Basics.Ctime, 0).UTC().Format(time.RFC3339)).Println()
	}
	if keybaseUser.Basics.Mtime != 0 {
		theme.Greenf("[+] ↳ Updated at: %s", time.Unix(keybaseUser.Basics.Mtime, 0).UTC().Format(time.RFC3339)).Println()
	}
	if keybaseUser.Profile.FullName != "" {
		theme.Greenf("[+] ↳ Name: %s", keybaseUser.Profile.FullName).Println()
	}
	if keybaseUser.Profile.Location != "" {
		theme.Greenf("[+] ↳ Current location: %s", keybaseUser.Profile.Location).Println()
	}
	if keybaseUser.Profile.Bio != "" {
		theme.Greenf("[+] ↳ Bio: %s", keybaseUser.Profile.Bio).Println()
	}
	if keybaseUser.Pictures.Primary != nil && keybaseUser.Pictures.Primary.URL != "" {
		theme.Greenf("[+] ↳ Avatar URL: %s", keybaseUser.Pictures.Primary.URL).Println()
	}
	if keybaseUser.Stellar.Primary != nil && keybaseUser.Stellar.Primary.AccountID != "" {
		theme.Greenf("[+] ↳ Stellar account: %s", keybaseUser.Stellar.Primary.AccountID).Println()
	}

	if len(keybaseUser.ProofsSummary.All) > 0 {
		fmt.Println(strings.Repeat("⎯", 85))
		if len(keybaseUser.ProofsSummary.All) == 1 {
			theme.Greenf("[+] An identity proof was found for %s:", username).Println()
		} else {
			theme.Greenf("[+] %d identity proofs found for %s:", len(keybaseUser.ProofsSummary.All), username).Println()
		}
		for _, proof := range keybaseUser.ProofsSummary.All {
			if proof.ServiceURL != "" {
				theme.Greenf("[+] ↳ %s: %s (%s)", proof.ProofType, proof.Nametag, proof.ServiceURL).Println()
			} else {
				theme.Greenf("[+] ↳ %s: %s", proof.ProofType, proof.Nametag).Println()
			}
		}
	}

	if len(keybaseUser.CryptocurrencyAddresses) > 0 {
		fmt.Println(strings.Repeat("⎯", 85))
		theme.Green("[+] Cryptocurrency addresses:").Println()
		coins := make([]string, 0, len(keybaseUser.CryptocurrencyAddresses))
		for coin := range keybaseUser.CryptocurrencyAddresses {
			coins = append(coins, coin)
		}
		sort.Strings(coins)
		for _, coin := range coins {
			for _, addr := range keybaseUser.CryptocurrencyAddresses[coin] {
				if addr.Address != "" {
					theme.Greenf("[+] ↳ %s: %s", coin, addr.Address).Println()
				}
			}
		}
	}

	if len(keybaseUser.Devices) > 0 {
		fmt.Println(strings.Repeat("⎯", 85))
		theme.Green("[+] Devices:").Println()
		devices := make([]KeybaseDevice, 0, len(keybaseUser.Devices))
		for _, device := range keybaseUser.Devices {
			devices = append(devices, device)
		}
		sort.Slice(devices, func(i, j int) bool {
			if devices[i].Type != devices[j].Type {
				return devices[i].Type < devices[j].Type
			}
			return devices[i].Name < devices[j].Name
		})
		for _, device := range devices {
			theme.Greenf("[+] ↳ %s: %s", device.Type, device.Name).Println()
		}
	}

	fmt.Println()
}
