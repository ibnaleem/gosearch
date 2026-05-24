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
	EmailHash        string               `json:"hash"`
	Username         string               `json:"requestHash"`
	PreferredUsername string               `json:"preferredUsername"`
	DisplayName      string               `json:"displayName"`
	AboutMe          string               `json:"aboutMe"`
	Emails           []GravatarUserEmails   `json:"emails"`
	Accounts         []GravatarUserAccounts `json:"accounts"`
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
	theme.Greenf("[+] Gravatar username found: %s", user.Username)

	if user.Username != user.PreferredUsername {
		theme.Greenf("[+] ↳ Preferred username: %s", user.PreferredUsername)
	}

	theme.Greenf("[+] ↳ About Me: %s", user.AboutMe)

	if len(user.Emails) == 0 {
		fmt.Println(strings.Repeat("-", 85))
		theme.Greenf("[+] ↳ SHA256 Email Hash: %s", user.EmailHash)
		theme.Green("[+] ↳ Hashcat command to crack this hash:")
		theme.Greenf("[+] ↳ hashcat -m 1400 -a 0 %s facebook-firstnames.txt -r rules/MISC/emails-combined.rule --bitmap-max 28", user.EmailHash)
		theme.Green("[+] ↳ Hashcat rules can be found @ https://github.com/ibnaleem/rules")
		theme.Green("[+] ↳ Wordlists can be found @ https://weakpass.com/wordlists?name=name")
		theme.Green("[+] ↳ You could also submit this hash to Hashmob.net if you cannot crack it")
		fmt.Println(strings.Repeat("-", 85))
	}

	if len(user.Emails) > 1 {
		fmt.Println(strings.Repeat("-", 85))
		theme.Greenf("[+] %d Emails found for %s:", len(user.Emails), user.Username)
		for _, email := range user.Emails {
			theme.Greenf("[+] ↳ %s", email.Email)
		}
		fmt.Println(strings.Repeat("-", 85))
	} else {
		theme.Greenf("[+] Email found for %s: %s", user.Username, user.Emails[0].Email)
	}

	if len(user.Accounts) == 0 {
		return
	}

	if len(user.Accounts) > 1 {
		fmt.Println(strings.Repeat("-", 85))
		theme.Greenf("[+] %d accounts found for %s:", len(user.Accounts), user.Username)
		for _, account := range user.Accounts {
			fmt.Println(strings.Repeat("-", 85))
			theme.Greenf("[+] ↳ Platform: %s", account.Name)
			theme.Greenf("[+] ↳ Account URL: %s", account.URL)
			theme.Greenf("[+] ↳ Username: %s", account.Username)
			fmt.Println(strings.Repeat("-", 85))
		}
	} else {
		fmt.Println(strings.Repeat("-", 85))
		theme.Greenf("[+] An account was found for %s:", user.Username)
		for _, account := range user.Accounts {
			theme.Greenf("[+] ↳ Platform: %s", account.Name)
			theme.Greenf("[+] ↳ Account URL: %s", account.URL)
			theme.Greenf("[+] ↳ Username: %s", account.Username)
		}
	}
}
