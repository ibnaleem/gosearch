package gravatar

import (
	"fmt"
	"strings"

	"github.com/ibnaleem/gosearch/internal/theme"
)

type GravatarResponse struct {
	Entry []GravatarUser `json:"entry"`
}

type GravatarUser struct {
	EmailHash         string                 `json:"hash"`
	Username          string                 `json:"requestHash"`
	PreferredUsername string                 `json:"preferredUsername"`
	DisplayName       string                 `json:"displayName"`
	AboutMe           string                 `json:"aboutMe"`
	Emails            []GravatarUserEmails   `json:"emails"`
	Accounts          []GravatarUserAccounts `json:"accounts"`
}

type GravatarUserEmails struct {
	Email string `json:"value"`
}

type GravatarUserAccounts struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Name     string `json:"name"`
}

func DisplayGravatarUserInfo(user GravatarUser) {
	theme.Greenf("[+] Gravatar username found: %s", user.Username).Println()

	if user.DisplayName != "" {
		theme.Greenf("[+] ↳ Display name: %s", user.DisplayName).Println()
	}

	if user.PreferredUsername != "" && user.Username != user.PreferredUsername {
		theme.Greenf("[+] ↳ Preferred username: %s", user.PreferredUsername).Println()
	}

	if user.AboutMe != "" {
		theme.Greenf("[+] ↳ About Me: %s", user.AboutMe).Println()
	}

	if len(user.Emails) == 0 {
		fmt.Println(strings.Repeat("⎯", 85))
		theme.Greenf("[+] ↳ SHA256 Email Hash: %s", user.EmailHash).Println()
		theme.Green("[+] ↳ Hashcat command to crack this hash:").Println()
		theme.Greenf("[+] ↳ hashcat -m 1400 -a 0 %s facebook-firstnames.txt -r rules/MISC/emails-combined.rule --bitmap-max 28", user.EmailHash).Println()
		theme.Green("[+] ↳ Hashcat rules can be found @ https://github.com/ibnaleem/rules").Println()
		theme.Green("[+] ↳ Wordlists can be found @ https://weakpass.com/wordlists?name=name").Println()
		theme.Green("[+] ↳ You could also submit this hash to Hashmob.net if you cannot crack it").Println()
		fmt.Println(strings.Repeat("⎯", 85))
	} else if len(user.Emails) == 1 {
		theme.Greenf("[+] ↳ Email: %s", user.Emails[0].Email).Println()
	} else {
		fmt.Println(strings.Repeat("⎯", 85))
		theme.Greenf("[+] %d emails found for %s:", len(user.Emails), user.Username).Println()
		for _, email := range user.Emails {
			theme.Greenf("[+] ↳ %s", email.Email).Println()
		}
		fmt.Println(strings.Repeat("⎯", 85))
	}

	if len(user.Accounts) == 0 {
		return
	}

	fmt.Println(strings.Repeat("⎯", 85))
	if len(user.Accounts) == 1 {
		theme.Greenf("[+] An account was found for %s:", user.Username).Println()
	} else {
		theme.Greenf("[+] %d accounts found for %s:", len(user.Accounts), user.Username).Println()
	}
	for _, account := range user.Accounts {
		fmt.Println(strings.Repeat("⎯", 85))
		theme.Greenf("[+] ↳ Platform: %s", account.Name).Println()
		theme.Greenf("[+] ↳ Account URL: %s", account.URL).Println()
		theme.Greenf("[+] ↳ Username: %s", account.Username).Println()
	}
	fmt.Println(strings.Repeat("⎯", 85))
}
