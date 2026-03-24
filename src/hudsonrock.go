// HudsonRock Module

package main

import (
	"io"
	"os"
	"fmt"
	"log"
	"sync"
	"strings"
	"net/http"
	"encoding/json"


	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

type HudsonRockResponse struct {
	Message  string    `json:"message"`
	Stealers []Stealer `json:"stealers"`
}

type Stealer struct {
	TotalCorporateServices int         `json:"total_corporate_services"`
	TotalUserServices      int         `json:"total_user_services"`
	DateCompromised        string      `json:"date_compromised"`
	StealerFamily          string      `json:"stealer_family"`
	ComputerName           string      `json:"computer_name"`
	OperatingSystem        string      `json:"operating_system"`
	MalwarePath            string      `json:"malware_path"`
	Antiviruses            interface{} `json:"antiviruses"`
	IP                     string      `json:"ip"`
	TopPasswords           []string    `json:"top_passwords"`
	TopLogins              []string    `json:"top_logins"`
}


func HudsonRock(username string, wg *sync.WaitGroup) {
	defer wg.Done()

	url := fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=%s", username)

	resp, err := http.Get(url)
	if err != nil {
		Redf("Error fetching HudsonRock data:").Print()
		White(" " + err.Error()).Println()
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Red("Error reading response:").Print()
		White(" " + err.Error()).Println()
		return
	}

	var response HudsonRockResponse
	if err := json.Unmarshal(body, &response); err != nil {
		Red("Error parsing JSON:").Print()
		White(" " + err.Error()).Println()
		return
	}

	if response.Message == "This username is not associated with a computer infected by an info-stealer. Visit https://www.hudsonrock.com/free-tools to discover additional free tools and Infostealers related data." {
		Green("✓ No info-stealer association found").Println()
		WriteToFile(username, ":: No info-stealer association found")
		return
	}

	Red("‼ Info-stealer compromise detected").Println()
	Yellow("  All credentials on this computer may be exposed").Println()

	table := tablewriter.NewTable(os.Stdout, tablewriter.WithHeaderConfig(tw.CellConfig{
		Formatting: tw.CellFormatting{
			AutoFormat: tw.Off,
		},
	}))
	table.Header([]any{
		Blue("#"),
		Blue("Stealer"),
		Blue("Date"),
		Blue("Computer"),
		Blue("Passwords"),
	})

	var fileContent strings.Builder

	for i, stealer := range response.Stealers {
		var avs string
		switch v := stealer.Antiviruses.(type) {
		case string:
			avs = v
		case []interface{}:
			parts := make([]string, len(v))
			for i, av := range v {
				parts[i] = fmt.Sprint(av)
			}
			avs = strings.Join(parts, ", ")
		}

		computerName := stealer.ComputerName
		if !strings.EqualFold(strings.TrimSpace(computerName), "Not Found") {
			computerName = Red(computerName).String()
		}
		table.Append([]string{
			fmt.Sprintf("%d", i+1),
			stealer.StealerFamily,
			formatStealerDate(stealer.DateCompromised),
			computerName,
			strings.Join(stealer.TopPasswords, "\n"),
		})

		fileContent.WriteString(fmt.Sprintf("[-] Stealer #%d\n", i+1))
		fileContent.WriteString(fmt.Sprintf(":: Family: %s\n", stealer.StealerFamily))
		fileContent.WriteString(fmt.Sprintf(":: Date: %s\n", stealer.DateCompromised))
		fileContent.WriteString(fmt.Sprintf(":: Computer: %s\n", stealer.ComputerName))
		fileContent.WriteString(fmt.Sprintf(":: OS: %s\n", stealer.OperatingSystem))
		fileContent.WriteString(fmt.Sprintf(":: Path: %s\n", stealer.MalwarePath))
		fileContent.WriteString(fmt.Sprintf(":: AV: %s\n", avs))
		fileContent.WriteString(fmt.Sprintf(":: IP: %s\n", stealer.IP))

		fileContent.WriteString(":: Passwords:\n")
		for _, p := range stealer.TopPasswords {
			fileContent.WriteString(fmt.Sprintf("   %s\n", p))
		}

		fileContent.WriteString(":: Logins:\n")
		for _, l := range stealer.TopLogins {
			fileContent.WriteString(fmt.Sprintf("   %s\n", l))
		}
		fileContent.WriteString("\n")
	}

	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}

	WriteToFile(username, fileContent.String())
}