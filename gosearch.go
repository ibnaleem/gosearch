// Created by github.com/ibnaleem & contributors
// Contribute & support: github.com/ibnaleem/gosearch

package main

import (
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/olekukonko/tablewriter/renderer"

	"github.com/andybalholm/brotli"
	"github.com/bytedance/sonic"
	"github.com/ibnaleem/gobreach"
	"github.com/inancgumus/screen"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

const ASCII = `
 ________  ________  ________  _______   ________  ________  ________  ___  ___     
|\   ____\|\   __  \|\   ____\|\  ___ \ |\   __  \|\   __  \|\   ____\|\  \|\  \    
\ \  \___|\ \  \|\  \ \  \___|\ \   __/|\ \  \|\  \ \  \|\  \ \  \___|\ \  \\\  \   
 \ \  \  __\ \  \\\  \ \_____  \ \  \_|/_\ \   __  \ \   _  _\ \  \    \ \   __  \  
  \ \  \|\  \ \  \\\  \|____|\  \ \  \_|\ \ \  \ \  \ \  \\  \\ \  \____\ \  \ \  \ 
   \ \_______\ \_______\____\_\  \ \_______\ \__\ \__\ \__\\ _\\ \_______\ \__\ \__\
    \|_______|\|_______|\_________\|_______|\|__|\|__|\|__|\|__|\|_______|\|__|\|__|
                       \|_________|

`

const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"

const VERSION = "v1.0.0"

var (
	tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		NextProtos:       []string{"http/1.1"},                                    
	}


	count atomic.Uint32

	CurrentTheme = DarkTheme

	mu sync.Mutex

	outputDir string = "." // Default output directory is the current directory
)

type Theme struct {
	Reset     string // Reset formatting
	Bold      string // Bold text
	Underline string // Underlined text
	Red       string // Red text
	Green     string // Green text
	Yellow    string // Yellow text
	Blue      string // Blue text
	Magenta   string // Magenta text
	Cyan      string // Cyan text
	White     string // White text
	Gray      string // Gray text
}

var LightTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[31m", // Bright red for light background
	Green:     "\033[32m", // Forest green
	Yellow:    "\033[33m", // Dark yellow
	Blue:      "\033[34m", // Navy blue
	Magenta:   "\033[35m", // Dark magenta
	Cyan:      "\033[36m", // Dark cyan
	White:     "\033[37m", // Black for light background
	Gray:      "\033[90m", // Dark gray
}

var DarkTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[91m", // Light red for dark background
	Green:     "\033[92m", // Light green
	Yellow:    "\033[93m", // Bright yellow
	Blue:      "\033[94m", // Light blue
	Magenta:   "\033[95m", // Light magenta
	Cyan:      "\033[96m", // Light cyan
	White:     "\033[97m", // White for dark background
	Gray:      "\033[37m", // Light gray
}

func init() {
	CurrentTheme = detectTheme()
}

type Website struct {
	Name            string   `json:"name"`                   
	BaseURL         string   `json:"base_url"`               
	URLProbe        string   `json:"url_probe,omitempty"`    
	FollowRedirects bool     `json:"follow_redirects"`       
	UserAgent       string   `json:"user_agent,omitempty"`   
	ErrorType       string   `json:"errorType"`              
	ErrorMsg        string   `json:"errorMsg,omitempty"`     
	ErrorCode       int      `json:"errorCode,omitempty"`    
	ResponseURL     string   `json:"response_url,omitempty"` 
	Cookies         []Cookie `json:"cookies,omitempty"`     
}

type Data struct {
	Websites []Website `json:"websites"`
}

type Cookie struct {
	Name  string `json:"name"` 
	Value string `json:"value"`
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

type HudsonRockResponse struct {
	Message  string    `json:"message"`
	Stealers []Stealer `json:"stealers"`
}

type WeakpassResponse struct {
	Type string `json:"type"`
	Hash string `json:"hash"`
	Pass string `json:"pass"`
}

type ProxyNova struct {
	Count int      `json:"count"`
	Lines []string `json:"lines"`
}

type Color string

func (c Color) String() string {
	return string(c)
}

func (c Color) Print() {
	fmt.Print(c)
}

func (c Color) Println() {
	fmt.Println(c)
}

func (c Color) Fprint(w io.Writer) {
	fmt.Fprint(w, c)
}

func (c Color) Fprintln(w io.Writer) {
	fmt.Fprintln(w, c)
}

func main() {

	var username string
	var apikey string

	usernameFlag := flag.String("u", "", "Username to search")
	usernameFlagLong := flag.String("username", "", "Username to search")
	noFalsePositivesFlag := flag.Bool("no-false-positives", false, "Do not show false positives")
	breachDirectoryAPIKey := flag.String("b", "", "Search Breach Directory with an API Key")
	breachDirectoryAPIKeyLong := flag.String("breach-directory", "", "Search Breach Directory with an API Key")
	outputFlag := flag.String("o", "", "Directory to save the output files (default: current directory)")
	outputFlagLong := flag.String("output", "", "Directory to save the output files (default: current directory)")

	flag.Parse()

	if *usernameFlag != "" {
		username = *usernameFlag
	} else if *usernameFlagLong != "" {
		username = *usernameFlagLong
	} else {
		fmt.Println("Usage: gosearch -u <username>\nIssues: https://github.com/ibnaleem/gosearch/issues")
		os.Exit(1)
	}

	if *outputFlag != "" {
		outputDir = *outputFlag
	} else if *outputFlagLong != "" {
		outputDir = *outputFlagLong
	} else {
		outputDir = "."
	}

	var wg sync.WaitGroup

	data, err := UnmarshalJSON()
	if err != nil {
		fmt.Printf("Error unmarshalling json: %v\n", err)
		os.Exit(1)
	}

	screen.Clear()
	fmt.Print(ASCII)
	fmt.Println(VERSION)
	fmt.Println(strings.Repeat("⎯", 85))
	fmt.Println(":: Username                              : ", username)
	fmt.Println(":: Websites                              : ", len(data.Websites))

	if *noFalsePositivesFlag {
		fmt.Println(":: No False Positives                    : ", *noFalsePositivesFlag)
	}

	fmt.Println(strings.Repeat("⎯", 85))
	fmt.Println()

	if !*noFalsePositivesFlag {
		fmt.Println("[!] A yellow link indicates that I was unable to verify whether the username exists on the platform.")
	}

	start := time.Now()

	wg.Add(len(data.Websites))
	go Search(data, username, *noFalsePositivesFlag, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	wg.Add(1)
	WriteToFile(username, strings.Repeat("⎯", 85))
	Yellow("[*] Searching HudsonRock's Cybercrime Intelligence Database...").Println()
	go HudsonRock(username, &wg)
	wg.Wait()

	if *breachDirectoryAPIKey != "" || *breachDirectoryAPIKeyLong != "" {
		if *breachDirectoryAPIKey != "" {
			apikey = *breachDirectoryAPIKey
		} else {
			apikey = *breachDirectoryAPIKeyLong
		}

		fmt.Println()
		fmt.Println()

		wg.Add(1)
		go SearchBreachDirectory(username, apikey, &wg)
		wg.Wait()
	}

	fmt.Println()
	fmt.Println()

	wg.Add(1)
	WriteToFile(username, strings.Repeat("⎯", 85))
	go SearchProxyNova(username, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	domains := BuildDomains(username)
	wg.Add(1)
	go SearchDomains(username, domains, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	elapsed := time.Since(start)

	table := tablewriter.NewTable(os.Stdout, tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{Borders: tw.BorderNone})))
	table.Append(Bold("Number of profiles found"), Red(count.Load()))
	table.Append(Bold("Total time taken"), Green(elapsed))
	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}

	WriteToFile(username, ":: Number of profiles found              : "+strconv.Itoa(int(count.Load())))
	WriteToFile(username, ":: Total time taken                      : "+elapsed.String())
}

func UnmarshalJSON() (Data, error) {
	// GoSearch relies on data.json to determine the websites to search for.
	// Instead of forcing users to manually download the data.json file, we will fetch the latest version from the repository.
	// Therefore, we will do the following:
	// 1. Delete the existing data.json file if it exists as it will be outdated in the future
	// 2. Read the latest data.json file from the repository
	// Bonus: it does not download the data.json file, it just reads it from the repository.

	// Delete existing data.json file
	err := os.Remove("data.json")
	if err != nil && !os.IsNotExist(err) {
		return Data{}, fmt.Errorf("error deleting old data.json: %w", err)
	}

	// Fetch JSON from repository
	url := "https://raw.githubusercontent.com/ibnaleem/gosearch/refs/heads/main/data.json"
	resp, err := http.Get(url)
	if err != nil {
		return Data{}, fmt.Errorf("error downloading data.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Data{}, fmt.Errorf("failed to download data.json, status code: %d", resp.StatusCode)
	}

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return Data{}, fmt.Errorf("error reading downloaded content: %w", err)
	}

	var data Data
	err = sonic.Unmarshal(jsonData, &data)
	if err != nil {
		return Data{}, fmt.Errorf("error unmarshalling JSON: %w", err)
	}

	return data, nil
}

func WriteToFile(username string, content string) {
	mu.Lock()
	defer mu.Unlock()

	if _, err := os.Stat(outputDir); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
				log.Fatal("Error creating output directory:", err)
			}
		} else {
			log.Fatal("Error checking output directory:", err)
		}
	}

	filePath := filepath.Join(outputDir, fmt.Sprintf("%s_%s.txt", username, time.Now().Format("2006-01-02")))

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if _, err = f.WriteString(content); err != nil {
		log.Fatal(err)
	}
}

func BuildURL(baseURL, username string) string {
	return strings.Replace(baseURL, "{}", username, 1)
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
	if err := sonic.Unmarshal(body, &response); err != nil {
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

func BuildDomains(username string) []string {
	tlds := []string{
		".com",
		".net",
		".org",
		".biz",
		".info",
		".name",
		".pro",
		".cat",
		".co",
		".me",
		".io",
		".tech",
		".dev",
		".app",
		".shop",
		".fail",
		".xyz",
		".blog",
		".portfolio",
		".store",
		".online",
		".about",
		".space",
		".lol",
		".fun",
		".social",
	}

	var domains []string
	for _, tld := range tlds {
		domains = append(domains, username+tld)
	}

	return domains
}

func SearchDomains(username string, domains []string, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{}
	Yellow("[*] Searching ", len(domains), " domains with the username ", username, "...").Println()

	domainCount := 0
	table := tablewriter.NewWriter(os.Stdout)
	table.Header("NO", "DOMAIN", "STATUS")

	// Counter for table rows
	x := 0
	for _, domain := range domains {
		url := "http://" + domain

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			fmt.Printf("Error creating request for %s: %v\n", domain, err)
			continue
		}
		req.Header.Set("User-Agent", DefaultUserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Cache-Control", "max-age=0")

		resp, err := client.Do(req)
		if err != nil {
			var netErr net.Error
			ok := errors.As(err, &netErr)
			noSuchHostError := strings.Contains(err.Error(), "no such host")
			networkTimeoutError := ok && netErr.Timeout()

			if !noSuchHostError && !networkTimeoutError {
				fmt.Printf("Error sending request for %s: %v\n", domain, err)
			}

			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			x++ // increase table rows
			table.Append(x, domain, Green(http.StatusOK))
			WriteToFile(username, "[+] 200 OK: "+domain)
			domainCount++
		}
	}

	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}
	if domainCount > 0 {
		Greenf("[+] Found %d domains with the username %s", domainCount, username).Println()
		WriteToFile(username, "[+] Found "+strconv.Itoa(domainCount)+" domains with the username: "+username)
	} else {
		Redf("[-] No domains found with the username %s", username).Println()
		WriteToFile(username, "[-] No domains found with the username: "+username)
	}
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
	err = sonic.Unmarshal(body, &response)
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

func CrackHash(hash string) string {
	client := &http.Client{}
	url := fmt.Sprintf("https://weakpass.com/api/v1/search/%s.json", hash)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function CrackHash: %v\n", err)
		return ""
	}

	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error fetching response in function CrackHash: %v\n", err)
		return ""
	}
	defer res.Body.Close()

	jsonData, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error reading response JSON: %v\n", err)
		return ""
	}

	var weakpass WeakpassResponse
	err = sonic.Unmarshal(jsonData, &weakpass)
	if err != nil {
		fmt.Printf("Error unmarshalling JSON: %v\n", err)
		return ""
	}
	return weakpass.Pass
}

func MakeRequestWithResponseURL(website Website, url string, username string) {
	// Some websites always return a 200 for existing and non-existing profiles.
	// If we do not follow redirects, we could get a 301 for existing profiles and 302 for non-existing profiles.
	// That is why we have the follow_redirects in our website struct.
	// However, sometimes the website returns 301 for existing profiles and non-existing profiles.
	// This means even if we do not follow redirects, we still get false positives.
	// To mitigate this, we can examine the response url to check for non-existing profiles.
	// Usually, a response url pointing to where the profile should be is returned for existing profiles.
	// If the response url is not pointing to where the profile should be, then the profile does not exist.

	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Jar: nil,
	}

	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithResponseURL: %v\n", err)
		return
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")

	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
	}

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return
	}

	formattedResponseURL := BuildURL(website.ResponseURL, username)
	if !(res.Request.URL.String() == formattedResponseURL) {
		url = BuildURL(website.BaseURL, username)
		Green("[+]", website.Name, ":", url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

func MakeRequestWithErrorCode(website Website, url string, username string) {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Jar: nil,
	}

	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorCode: %v\n", err)
		return
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")

	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
	}

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return
	}

	if res.StatusCode != website.ErrorCode {
		url = BuildURL(website.BaseURL, username)
		Green("[+] ", website.Name, ":", url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

func MakeRequestWithErrorMsg(website Website, url string, username string) {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Jar: nil,
	}

	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorMsg: %v\n", err)
		return
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")

	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
	}

	res, err := client.Do(req)
	if err != nil {
		return
	}
	var reader io.ReadCloser
	switch res.Header.Get("Content-Encoding") {
	case "gzip":
		gzReader, err := gzip.NewReader(res.Body)
		if err != nil {
			fmt.Printf("Error creating gzip reader: %v\n", err)
			return
		}
		reader = gzReader
	case "deflate":
		zlibReader, err := zlib.NewReader(res.Body)
		if err != nil {
			fmt.Printf("Error creating deflate reader: %v\n", err)
			return
		}
		reader = zlibReader
	case "br":
		reader = io.NopCloser(brotli.NewReader(res.Body))
	default:
		reader = res.Body
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, website.ErrorMsg) {
		url = BuildURL(website.BaseURL, username)
		Green("[+] ", website.Name, ":", url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

func MakeRequestWithProfilePresence(website Website, url string, username string) {
	// Some websites have an indicator that a profile exists
	// but do not have an indicator when a profile does not exist.
	// If a profile indicator is not found, we can assume that the profile does not exist.

	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Jar: nil,
	}

	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorMsg: %v\n", err)
		return
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")

	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
	}

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, website.ErrorMsg) {
		Greenf("[+] %s: %s", website.Name, url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

func Search(data Data, username string, noFalsePositives bool, wg *sync.WaitGroup) {
	for _, website := range data.Websites {
		go func(website Website) {
			var url string
			defer wg.Done()

			if website.URLProbe != "" {
				url = BuildURL(website.URLProbe, username)
			} else {
				url = BuildURL(website.BaseURL, username)
			}

			switch website.ErrorType {
			case "status_code":
				MakeRequestWithErrorCode(website, url, username)
			case "errorMsg":
				MakeRequestWithErrorMsg(website, url, username)
			case "profilePresence":
				MakeRequestWithProfilePresence(website, url, username)
			case "response_url":
				MakeRequestWithResponseURL(website, url, username)
			default:
				if !noFalsePositives {
					Yellowf("[?] %s: %s", website.Name, url).Println()
					WriteToFile(username, "[?] "+url+"\n")
					count.Add(1)
				}
			}
		}(website)
	}
}

func DeleteOldFile(username string) {
	filename := fmt.Sprintf("%s.txt", username)
	os.Remove(filename)
}

func Text(s string, colorCode string) Color {
	return Color(colorCode + s + CurrentTheme.Reset)
}

func Red(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Red)
}

func Green(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Green)
}

func Yellow(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Yellow)
}

func Blue(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Blue)
}

func Cyan(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Cyan)
}

func Magenta(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Magenta)
}

func White(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.White)
}

func Gray(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Gray)
}

func Redf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Red)
}

func Greenf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Green)
}

func Yellowf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Yellow)
}

func Bluef(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Blue)
}

func Cyanf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Cyan)
}

func Magentaf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Magenta)
}

func Whitef(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.White)
}

func Grayf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Gray)
}

func Bold(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Bold)
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
		return t.Format("Jan 2, 2006") // e.g., "May 15, 2025"
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func detectTheme() Theme {
	colorfgbg := os.Getenv("COLORFGBG")
	if strings.Contains(colorfgbg, ";0") {
		return DarkTheme // Dark background
	} else if strings.Contains(colorfgbg, ";15") {
		return LightTheme // Light background
	}
	return DarkTheme // Default
}