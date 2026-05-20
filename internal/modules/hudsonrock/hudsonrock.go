package hudsonrock

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"

	"github.com/ibnaleem/gosearch/internal/theme"
	"github.com/ibnaleem/gosearch/internal/utils"
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

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func formatStealerDate(dateStr string) string {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return dateStr
	}

	now := time.Now()
	diff := now.Sub(t)

	switch {
	case diff < time.Hour:
		return "just now"
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		return fmt.Sprintf("%d hour%s ago", hours, plural(hours))
	case diff < 7*24*time.Hour:
		days := int(diff.Hours() / 24)
		return fmt.Sprintf("%d day%s ago", days, plural(days))
	default:
		return t.Format("Jan 2, 2006")
	}
}

func HudsonRock(username string, wg *sync.WaitGroup) {
	defer wg.Done()

	url := fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=%s", username)

	resp, err := http.Get(url)
	if err != nil {
		theme.Redf("Error fetching HudsonRock data:").Print()
		theme.White(" " + err.Error()).Println()
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		theme.Red("Error reading response:").Print()
		theme.White(" " + err.Error()).Println()
		return
	}

	var response HudsonRockResponse
	if err := json.Unmarshal(body, &response); err != nil {
		theme.Red("Error parsing JSON:").Print()
		theme.White(" " + err.Error()).Println()
		return
	}

	if response.Message == "This username is not associated with a computer infected by an info-stealer. Visit https://www.hudsonrock.com/free-tools to discover additional free tools and Infostealers related data." {
		theme.Green("✓ No info-stealer association found").Println()
		utils.WriteToFile(username, ":: No info-stealer association found")
		return
	}

	theme.Red("‼ Info-stealer compromise detected").Println()
	theme.Yellow("  All credentials on this computer may be exposed").Println()

	table := tablewriter.NewTable(os.Stdout, tablewriter.WithHeaderConfig(tw.CellConfig{
		Formatting: tw.CellFormatting{
			AutoFormat: tw.Off,
		},
	}))
	table.Header([]any{
		theme.Blue("#"),
		theme.Blue("Stealer"),
		theme.Blue("Date"),
		theme.Blue("Computer"),
		theme.Blue("Passwords"),
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
			computerName = theme.Red(computerName).String()
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

	utils.WriteToFile(username, fileContent.String())
}
