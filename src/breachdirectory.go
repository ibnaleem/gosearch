// BreachDirectory Module

package main

import (	
	"log"
	"sync"

	"github.com/ibnaleem/gobreach"
)

func SearchBreachDirectory(username string, apikey string, wg *sync.WaitGroup) {
	defer wg.Done()

	client, err := gobreach.NewBreachDirectoryClient(apikey)
	if err != nil {
		log.Fatal(err)
	}

	Yellow("[*] Searching ", username, " on Breach Directory for any compromised passwords...").Println()

	response, err := client.Search(username)
	if err != nil {
		log.Fatal(err)
	}

	if response.Found == 0 {
		Redf("[-] No breaches found for %s.", username).Println()
		WriteToFile(username, "[-] No breaches found on Breach Directory for: "+username)
	}

	Greenf("[+] Found %d breaches for %s:\n", response.Found, username).Println()
	for _, entry := range response.Result {
		pass := CrackHash(entry.Hash)
		if pass != "" {
			Green("[+] Password:", pass).Println()
			WriteToFile(username, "[+] Password: "+pass)
		} else {
			Green("[+] Password:", entry.Password).Println()
			WriteToFile(username, "[+] Password: "+entry.Password)
		}

		Green("[+] SHA1:", entry.Sha1).Println()
		Green("[+] Source:", entry.Sources).Println()
		Green("[+] SHA1:", entry.Sha1)
		WriteToFile(username, "[+] Source: "+entry.Sources)
	}
}