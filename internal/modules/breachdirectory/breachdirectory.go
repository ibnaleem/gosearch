package breachdirectory

import (
	"log"
	"sync"

	"github.com/ibnaleem/gobreach"

	"github.com/ibnaleem/gosearch/internal/modules/weakpass"
	"github.com/ibnaleem/gosearch/internal/theme"
	"github.com/ibnaleem/gosearch/internal/utils"
)

func SearchBreachDirectory(username string, apikey string, wg *sync.WaitGroup) {
	defer wg.Done()

	client, err := gobreach.NewBreachDirectoryClient(apikey)
	if err != nil {
		log.Fatal(err)
	}

	theme.Yellow("[*] Searching ", username, " on Breach Directory for any compromised passwords...").Println()

	response, err := client.Search(username)
	if err != nil {
		log.Fatal(err)
	}

	if response.Found == 0 {
		theme.Redf("[-] No breaches found for %s.", username).Println()
		utils.WriteToFile(username, "[-] No breaches found on Breach Directory for: "+username)
	}

	theme.Greenf("[+] Found %d breaches for %s:\n", response.Found, username).Println()
	for _, entry := range response.Result {
		pass := weakpass.CrackHash(entry.Hash)
		if pass != "" {
			theme.Green("[+] Password:", pass).Println()
			utils.WriteToFile(username, "[+] Password: "+pass)
		} else {
			theme.Green("[+] Password:", entry.Password).Println()
			utils.WriteToFile(username, "[+] Password: "+entry.Password)
		}

		theme.Green("[+] SHA1:", entry.Sha1).Println()
		theme.Green("[+] Source:", entry.Sources).Println()
		utils.WriteToFile(username, "[+] Source: "+entry.Sources)
	}
}
