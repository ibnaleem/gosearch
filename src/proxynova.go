// ProxyNova Module

package main

import (
	"os"
	"io"
	"fmt"
	"log"
	"sync"
	"strings"
	"net/http"
	"encoding/json"

	"github.com/olekukonko/tablewriter"
)

type ProxyNova struct {
	Count int      `json:"count"`
	Lines []string `json:"lines"`
}

func SearchProxyNova(username string, wg *sync.WaitGroup) {
	defer wg.Done()

	Yellow("[*] Searching ", username, " on ProxyNova for any compromised passwords...").Println()

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, "https://api.proxynova.com/comb?query="+username, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response in SearchProxyNova function:", err)
		return
	}

	var response ProxyNova
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error parsing JSON in SearchProxyNova function:", err)
		return
	}

	if response.Count > 0 {
		table := tablewriter.NewTable(os.Stdout)
		table.Header("No", "Email", "Password")
		Greenf("[+] Found %d compromised passwords for %s:\n", response.Count, username).Println()
		for i, element := range response.Lines {
			parts := strings.Split(element, ":")
			if len(parts) == 2 {
				email := parts[0]
				password := parts[1]
				table.Append(i+1, Green(email), Red(password))
				WriteToFile(username, "[+] Email: "+email+"\n"+"[+] Password: "+password+"\n\n")
			}
		}
		if err := table.Render(); err != nil {
			log.Printf("table render failed: %v", err)
		}
	} else {
		Red("[-] No compromised passwords found for ", username, ".").Println()
	}
}