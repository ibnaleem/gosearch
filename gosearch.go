// Package main contains the implementation of GoSearch, a tool for searching usernames across various websites
// and checking for compromised credentials.
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

// GoSearch ASCII logo displayed at program start.
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

// User-Agent header used in HTTP requests to mimic a browser.
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"

// GoSearch version number.
const VERSION = "v1.0.0"

var (

	// tlsConfig defines the TLS configuration for secure HTTP requests.
	tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12, // Minimum TLS version
		CipherSuites: []uint16{ // Supported cipher suites
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
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}, // Preferred elliptic curves
		NextProtos:       []string{"http/1.1"},                                    // Supported protocols
	}

	// count tracks the number of found profiles using atomic operations for thread safety.
	count atomic.Uint32

	// CurrentTheme holds the active color theme for terminal output.
	CurrentTheme = DarkTheme

	// file mutext
	mu sync.Mutex

	// outputDir is the directory where output files are saved.
	outputDir string = "." // Default output directory is the current directory
)

// Theme defines color codes for terminal output styling.
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

// LightTheme defines colors optimized for light terminal backgrounds.
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

// DarkTheme defines colors optimized for dark terminal backgrounds.
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

// init sets the initial theme based on terminal background detection.
func init() {
	// Override theme based on auto-detection
	CurrentTheme = detectTheme()
}

// Website represents a website configuration for searching usernames.
type Website struct {
	Name            string   `json:"name"`                   // Website name
	BaseURL         string   `json:"base_url"`               // Base URL template
	URLProbe        string   `json:"url_probe,omitempty"`    // Optional probe URL
	FollowRedirects bool     `json:"follow_redirects"`       // Whether to follow HTTP redirects
	UserAgent       string   `json:"user_agent,omitempty"`   // Custom User-Agent, if any
	ErrorType       string   `json:"errorType"`              // Type of error checking
	ErrorMsg        string   `json:"errorMsg,omitempty"`     // Expected error message for non-existent profiles
	ErrorCode       int      `json:"errorCode,omitempty"`    // Expected HTTP status code for non-existent profiles
	ResponseURL     string   `json:"response_url,omitempty"` // Expected response URL for existing profiles
	Cookies         []Cookie `json:"cookies,omitempty"`      // Cookies to include in requests
}

// Data holds the list of websites to search.
type Data struct {
	Websites []Website `json:"websites"` // List of website configurations
}

// Cookie represents an HTTP cookie.
type Cookie struct {
	Name  string `json:"name"`  // Cookie name
	Value string `json:"value"` // Cookie value
}

// Stealer represents data from an info-stealer compromise.
type Stealer struct {
	TotalCorporateServices int         `json:"total_corporate_services"` // Number of corporate services compromised
	TotalUserServices      int         `json:"total_user_services"`      // Number of user services compromised
	DateCompromised        string      `json:"date_compromised"`         // Date of compromise
	StealerFamily          string      `json:"stealer_family"`           // Type of stealer malware
	ComputerName           string      `json:"computer_name"`            // Name of compromised computer
	OperatingSystem        string      `json:"operating_system"`         // Operating system of compromised computer
	MalwarePath            string      `json:"malware_path"`             // Path of malware on compromised system
	Antiviruses            interface{} `json:"antiviruses"`              // Antivirus software detected
	IP                     string      `json:"ip"`                       // IP address of compromised system
	TopPasswords           []string    `json:"top_passwords"`            // Commonly used passwords
	TopLogins              []string    `json:"top_logins"`               // Commonly used logins
}

// HudsonRockResponse represents the response from HudsonRock's API.
type HudsonRockResponse struct {
	Message  string    `json:"message"`  // Response message
	Stealers []Stealer `json:"stealers"` // List of stealer data
}

// WeakpassResponse represents the response from Weakpass API for hash cracking.
type WeakpassResponse struct {
	Type string `json:"type"` // Hash type
	Hash string `json:"hash"` // Hash value
	Pass string `json:"pass"` // Cracked password
}

// ProxyNova represents the response from ProxyNova API for compromised passwords.
type ProxyNova struct {
	Count int      `json:"count"` // Number of compromised credentials
	Lines []string `json:"lines"` // List of credential pairs
}

// HIBPBreach represents a breach from Have I Been Pwned API.
type HIBPBreach struct {
	Name         string `json:"Name"`         // Breach name
	Title        string `json:"Title"`        // Breach title
	Domain       string `json:"Domain"`       // Affected domain
	BreachDate   string `json:"BreachDate"`   // Date of breach
	PwnCount     int    `json:"PwnCount"`     // Number of accounts affected
	Description  string `json:"Description"`  // Breach description
	DataClasses  []string `json:"DataClasses"` // Types of data exposed
	IsVerified   bool   `json:"IsVerified"`   // Whether breach is verified
	IsSensitive  bool   `json:"IsSensitive"`  // Whether breach contains sensitive data
}

// LeakCheckResponse represents response from LeakCheck API.
type LeakCheckResponse struct {
	Success bool              `json:"success"` // Whether request succeeded
	Found   int               `json:"found"`   // Number of results found
	Result  []LeakCheckResult `json:"result"`  // List of leak results
}

// LeakCheckResult represents a single leak result.
type LeakCheckResult struct {
	Email    string   `json:"email"`    // Leaked email
	Username string   `json:"username"` // Leaked username
	Password string   `json:"password"` // Leaked password (if available)
	Sources  []string `json:"sources"`  // Leak sources
}

// DeHashedResponse represents response from DeHashed API.
type DeHashedResponse struct {
	Balance int              `json:"balance"` // API credits remaining
	Took    string           `json:"took"`    // Query time
	Total   int              `json:"total"`   // Total results
	Entries []DeHashedEntry  `json:"entries"` // List of entries
}

// DeHashedEntry represents a single DeHashed result.
type DeHashedEntry struct {
	ID           string `json:"id"`            // Entry ID
	Email        string `json:"email"`         // Email address
	Username     string `json:"username"`      // Username
	Password     string `json:"password"`      // Password (plaintext if available)
	HashedPassword string `json:"hashed_password"` // Hashed password
	Database     string `json:"database_name"` // Source database
}

// IntelXResponse represents response from Intelligence X API.
type IntelXResponse struct {
	ID      string        `json:"id"`      // Search ID
	Status  int           `json:"status"`  // Search status
	Records []IntelXRecord `json:"records"` // Search results
}

// IntelXRecord represents a single Intelligence X result.
type IntelXRecord struct {
	SystemID   string `json:"systemid"`   // System ID
	Name       string `json:"name"`       // Result name
	Date       string `json:"date"`       // Date found
	Bucket     string `json:"bucket"`     // Source bucket
	Type       int    `json:"type"`       // Result type
	MediaType  int    `json:"mediah"`     // Media type
}

// GitHubCodeSearchResponse represents GitHub code search API response.
type GitHubCodeSearchResponse struct {
	TotalCount int                   `json:"total_count"` // Total results
	Items      []GitHubCodeSearchItem `json:"items"`       // Search results
}

// GitHubCodeSearchItem represents a single code search result.
type GitHubCodeSearchItem struct {
	Name       string `json:"name"`       // File name
	Path       string `json:"path"`       // File path
	HTMLURL    string `json:"html_url"`   // URL to view file
	Repository struct {
		FullName string `json:"full_name"` // Repo owner/name
		HTMLURL  string `json:"html_url"`  // Repo URL
	} `json:"repository"`
}

// Color represents a colored string for terminal output.
type Color string

// String returns the colored string.
func (c Color) String() string {
	return string(c)
}

// Print prints the colored text without a newline.
func (c Color) Print() {
	fmt.Print(c)
}

// Println prints the colored text with a newline.
func (c Color) Println() {
	fmt.Println(c)
}

// Fprint writes the colored text to an io.Writer.
func (c Color) Fprint(w io.Writer) {
	fmt.Fprint(w, c)
}

// Fprintln writes the colored text to an io.Writer with a newline.
func (c Color) Fprintln(w io.Writer) {
	fmt.Fprintln(w, c)
}

// main is the entry point of the program, handling command-line arguments and orchestrating searches.
func main() {
	// Variables to store username and API key
	var username string
	var apikey string

	// Define command-line flags
	usernameFlag := flag.String("u", "", "Username to search")
	usernameFlagLong := flag.String("username", "", "Username to search")
	noFalsePositivesFlag := flag.Bool("no-false-positives", false, "Do not show false positives")
	breachDirectoryAPIKey := flag.String("b", "", "Search Breach Directory with an API Key")
	breachDirectoryAPIKeyLong := flag.String("breach-directory", "", "Search Breach Directory with an API Key")
	hibpAPIKey := flag.String("hibp", "", "Search Have I Been Pwned with an API Key")
	leakcheckAPIKey := flag.String("leakcheck", "", "Search LeakCheck.io with an API Key")
	dehashedAPIKey := flag.String("dehashed", "", "Search DeHashed with API credentials (email:api_key)")
	intelxAPIKey := flag.String("intelx", "", "Search Intelligence X with an API Key")
	githubToken := flag.String("github-token", "", "GitHub token for code search (searches for leaked credentials in repos)")
	outputFlag := flag.String("o", "", "Directory to save the output files (default: current directory)")
	outputFlagLong := flag.String("output", "", "Directory to save the output files (default: current directory)")

	// Parse command-line flags
	flag.Parse()

	// Determine username from flags or arguments
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

	// Delete any existing output file for the username
	// DeleteOldFile(username)
	// Initialize a wait group for concurrent operations
	var wg sync.WaitGroup

	// Load website data from JSON
	data, err := UnmarshalJSON()
	if err != nil {
		fmt.Printf("Error unmarshalling json: %v\n", err)
		os.Exit(1)
	}

	// Clear the terminal screen
	screen.Clear()
	// Display ASCII logo and version
	fmt.Print(ASCII)
	fmt.Println(VERSION)
	// Print separator line
	fmt.Println(strings.Repeat("⎯", 85))
	// Display search parameters
	fmt.Println(":: Username                              : ", username)
	fmt.Println(":: Websites                              : ", len(data.Websites))

	// Display false positives setting if enabled
	if *noFalsePositivesFlag {
		fmt.Println(":: No False Positives                    : ", *noFalsePositivesFlag)
	}

	// Print separator line
	fmt.Println(strings.Repeat("⎯", 85))
	fmt.Println()

	// Warn about false positives if not disabled
	if !*noFalsePositivesFlag {
		fmt.Println("[!] A yellow link indicates that I was unable to verify whether the username exists on the platform.")
	}

	// Record start time for performance measurement
	start := time.Now()

	// Start searching websites concurrently
	wg.Add(len(data.Websites))
	go Search(data, username, *noFalsePositivesFlag, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	// Search HudsonRock's database
	wg.Add(1)
	WriteToFile(username, strings.Repeat("⎯", 85))
	Yellow("[*] Searching HudsonRock's Cybercrime Intelligence Database...").Println()
	go HudsonRock(username, &wg)
	wg.Wait()

	// Search Breach Directory if API key is provided
	if *breachDirectoryAPIKey != "" || *breachDirectoryAPIKeyLong != "" {
		if *breachDirectoryAPIKey != "" {
			apikey = *breachDirectoryAPIKey
		} else {
			apikey = *breachDirectoryAPIKeyLong
		}

		fmt.Println()
		fmt.Println()

		//fmt.Println(strings.Repeat("⎯", 85))
		//strings.Repeat("⎯", 85)
		wg.Add(1)
		go SearchBreachDirectory(username, apikey, &wg)
		wg.Wait()
	}

	// Search Have I Been Pwned if API key is provided
	if *hibpAPIKey != "" {
		fmt.Println()
		fmt.Println()
		wg.Add(1)
		go SearchHIBP(username, *hibpAPIKey, &wg)
		wg.Wait()
	}

	// Search LeakCheck if API key is provided
	if *leakcheckAPIKey != "" {
		fmt.Println()
		fmt.Println()
		wg.Add(1)
		go SearchLeakCheck(username, *leakcheckAPIKey, &wg)
		wg.Wait()
	}

	// Search DeHashed if API credentials are provided
	if *dehashedAPIKey != "" {
		fmt.Println()
		fmt.Println()
		wg.Add(1)
		go SearchDeHashed(username, *dehashedAPIKey, &wg)
		wg.Wait()
	}

	// Search Intelligence X if API key is provided
	if *intelxAPIKey != "" {
		fmt.Println()
		fmt.Println()
		wg.Add(1)
		go SearchIntelX(username, *intelxAPIKey, &wg)
		wg.Wait()
	}

	// Search GitHub for leaked credentials if token is provided
	if *githubToken != "" {
		fmt.Println()
		fmt.Println()
		wg.Add(1)
		go SearchGitHubCode(username, *githubToken, &wg)
		wg.Wait()
	}

	fmt.Println()
	fmt.Println()

	// Search ProxyNova for compromised passwords
	wg.Add(1)
	// fmt.Println(strings.Repeat("⎯", 85))
	WriteToFile(username, strings.Repeat("⎯", 85))
	go SearchProxyNova(username, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	// Search for domains associated with the username
	domains := BuildDomains(username)
	//fmt.Println(strings.Repeat("⎯", 85))
	wg.Add(1)
	go SearchDomains(username, domains, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	// Calculate and display elapsed time
	elapsed := time.Since(start)

	table := tablewriter.NewTable(os.Stdout, tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{Borders: tw.BorderNone})))
	table.Append(Bold("Number of profiles found"), Red(count.Load()))
	table.Append(Bold("Total time taken"), Green(elapsed))
	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}
	// fmt.Println(strings.Repeat("⎯", 85))

	WriteToFile(username, ":: Number of profiles found              : "+strconv.Itoa(int(count.Load())))
	WriteToFile(username, ":: Total time taken                      : "+elapsed.String())
}

// UnmarshalJSON fetches and parses the website configuration from a remote JSON file.
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

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return Data{}, fmt.Errorf("failed to download data.json, status code: %d", resp.StatusCode)
	}

	// Read response body
	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return Data{}, fmt.Errorf("error reading downloaded content: %w", err)
	}

	// Unmarshal JSON into Data struct
	var data Data
	err = sonic.Unmarshal(jsonData, &data)
	if err != nil {
		return Data{}, fmt.Errorf("error unmarshalling JSON: %w", err)
	}

	return data, nil
}

// WriteToFile appends content to a file named after the username.
func WriteToFile(username string, content string) {
	mu.Lock()
	defer mu.Unlock()

	if _, err := os.Stat(outputDir); err != nil {
		if os.IsNotExist(err) {
			// Create output directory if it doesn't exist
			if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
				log.Fatal("Error creating output directory:", err)
			}
		} else {
			log.Fatal("Error checking output directory:", err)
		}
	}

	// Construct filename
	filePath := filepath.Join(outputDir, fmt.Sprintf("%s_%s.txt", username, time.Now().Format("2006-01-02")))

	// Open file in append mode, create if it doesn't exist
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// Write content to file
	if _, err = f.WriteString(content); err != nil {
		log.Fatal(err)
	}
}

// BuildURL constructs a URL by replacing the placeholder with the username.
func BuildURL(baseURL, username string) string {
	return strings.Replace(baseURL, "{}", username, 1)
}

// HudsonRock searches HudsonRock's database for info-stealer compromises.
func HudsonRock(username string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Construct API URL
	url := fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=%s", username)

	// Send HTTP request
	resp, err := http.Get(url)
	if err != nil {
		Redf("Error fetching HudsonRock data:").Print()
		White(" " + err.Error()).Println()
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Red("Error reading response:").Print()
		White(" " + err.Error()).Println()
		return
	}

	// Parse JSON response
	var response HudsonRockResponse
	if err := sonic.Unmarshal(body, &response); err != nil {
		Red("Error parsing JSON:").Print()
		White(" " + err.Error()).Println()
		return
	}

	// Check if no compromises were found
	if response.Message == "This username is not associated with a computer infected by an info-stealer. Visit https://www.hudsonrock.com/free-tools to discover additional free tools and Infostealers related data." {
		Green("✓ No info-stealer association found").Println()
		WriteToFile(username, ":: No info-stealer association found")
		return
	}

	// Display warning for detected compromises
	Red("‼ Info-stealer compromise detected").Println()
	Yellow("  All credentials on this computer may be exposed").Println()

	// Initialize table for terminal output
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

	// Buffer for file output
	var fileContent strings.Builder

	// Process each stealer entry
	for i, stealer := range response.Stealers {
		// Format antiviruses
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

		// Highlight computer name if valid
		computerName := stealer.ComputerName
		if !strings.EqualFold(strings.TrimSpace(computerName), "Not Found") {
			computerName = Red(computerName).String()
		}
		// Add to terminal table
		table.Append([]string{
			fmt.Sprintf("%d", i+1),
			stealer.StealerFamily,
			formatStealerDate(stealer.DateCompromised),
			computerName,
			strings.Join(stealer.TopPasswords, "\n"),
		})

		// Add to file content
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

	// Render table to terminal
	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}

	// Write all content to file
	WriteToFile(username, fileContent.String())
}

// BuildDomains generates a list of potential domains using the username and common TLDs.
func BuildDomains(username string) []string {
	// List of common top-level domains
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

	// Generate domains by appending TLDs to username
	var domains []string
	for _, tld := range tlds {
		domains = append(domains, username+tld)
	}

	return domains
}

// SearchDomains checks if domains associated with the username exist.
func SearchDomains(username string, domains []string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Initialize HTTP client
	client := &http.Client{}
	Yellow("[*] Searching ", len(domains), " domains with the username ", username, "...").Println()

	// Track number of found domains
	domainCount := 0
	// Initialize table for output
	table := tablewriter.NewWriter(os.Stdout)
	table.Header("NO", "DOMAIN", "STATUS")

	// Counter for table rows
	x := 0
	// Check each domain
	for _, domain := range domains {
		url := "http://" + domain

		// Create HTTP request
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			fmt.Printf("Error creating request for %s: %v\n", domain, err)
			continue
		}
		// Set request headers
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

		// Send request
		resp, err := client.Do(req)
		if err != nil {
			var netErr net.Error
			ok := errors.As(err, &netErr)
			// Check for specific network errors indicating non-existent domains
			noSuchHostError := strings.Contains(err.Error(), "no such host")
			networkTimeoutError := ok && netErr.Timeout()

			if !noSuchHostError && !networkTimeoutError {
				fmt.Printf("Error sending request for %s: %v\n", domain, err)
			}

			continue
		}
		defer resp.Body.Close()

		// Check if domain exists (HTTP 200)
		if resp.StatusCode == http.StatusOK {
			x++
			table.Append(x, domain, Green(http.StatusOK))
			WriteToFile(username, "[+] 200 OK: "+domain)
			domainCount++
		}
	}

	// Render table
	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}
	// Display results
	if domainCount > 0 {
		Greenf("[+] Found %d domains with the username %s", domainCount, username).Println()
		WriteToFile(username, "[+] Found "+strconv.Itoa(domainCount)+" domains with the username: "+username)
	} else {
		Redf("[-] No domains found with the username %s", username).Println()
		WriteToFile(username, "[-] No domains found with the username: "+username)
	}
}

// SearchProxyNova checks ProxyNova for compromised passwords associated with the username.
func SearchProxyNova(username string, wg *sync.WaitGroup) {
	defer wg.Done()

	Yellow("[*] Searching ", username, " on ProxyNova for any compromised passwords...").Println()

	// Initialize HTTP client
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest(http.MethodGet, "https://api.proxynova.com/comb?query="+username, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response in SearchProxyNova function:", err)
		return
	}

	// Parse JSON response
	var response ProxyNova
	err = sonic.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error parsing JSON in SearchProxyNova function:", err)
		return
	}

	// Check if compromised credentials were found
	if response.Count > 0 {
		// Initialize table
		table := tablewriter.NewTable(os.Stdout)
		table.Header("No", "Email", "Password")
		Greenf("[+] Found %d compromised passwords for %s:\n", response.Count, username).Println()
		// Process each credential
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

// SearchBreachDirectory searches Breach Directory for compromised credentials using an API key.
func SearchBreachDirectory(username string, apikey string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Initialize Breach Directory client
	client, err := gobreach.NewBreachDirectoryClient(apikey)
	if err != nil {
		log.Fatal(err)
	}

	Yellow("[*] Searching ", username, " on Breach Directory for any compromised passwords...").Println()

	// Search for breaches
	response, err := client.Search(username)
	if err != nil {
		log.Fatal(err)
	}

	// Check if no breaches were found
	if response.Found == 0 {
		Redf("[-] No breaches found for %s.", username).Println()
		WriteToFile(username, "[-] No breaches found on Breach Directory for: "+username)
	}

	// Display found breaches
	Greenf("[+] Found %d breaches for %s:\n", response.Found, username).Println()
	for _, entry := range response.Result {
		// Attempt to crack hash
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

// SearchHIBP searches Have I Been Pwned for breaches associated with an email/username.
func SearchHIBP(username string, apikey string, wg *sync.WaitGroup) {
	defer wg.Done()

	Yellow("[*] Searching ", username, " on Have I Been Pwned...").Println()
	WriteToFile(username, strings.Repeat("⎯", 85))
	WriteToFile(username, "[*] Have I Been Pwned Results:")

	// Initialize HTTP client
	client := &http.Client{Timeout: 30 * time.Second}

	// Construct API URL - HIBP can search by email or username
	url := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false", username)

	// Create request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		Redf("[-] Error creating HIBP request: %v", err).Println()
		return
	}

	// Set required headers
	req.Header.Set("User-Agent", "GoSearch-OSINT")
	req.Header.Set("hibp-api-key", apikey)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		Redf("[-] Error querying HIBP: %v", err).Println()
		return
	}
	defer resp.Body.Close()

	// Handle rate limiting
	if resp.StatusCode == 429 {
		Yellow("[!] HIBP rate limited. Try again later.").Println()
		return
	}

	// Handle not found
	if resp.StatusCode == 404 {
		Green("[+] Good news! ", username, " was not found in any breaches on HIBP.").Println()
		WriteToFile(username, "[+] No breaches found on Have I Been Pwned")
		return
	}

	// Handle unauthorized
	if resp.StatusCode == 401 {
		Redf("[-] Invalid HIBP API key. Get one at: https://haveibeenpwned.com/API/Key").Println()
		return
	}

	if resp.StatusCode != 200 {
		Redf("[-] HIBP returned status: %d", resp.StatusCode).Println()
		return
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Redf("[-] Error reading HIBP response: %v", err).Println()
		return
	}

	// Parse breaches
	var breaches []HIBPBreach
	err = sonic.Unmarshal(body, &breaches)
	if err != nil {
		Redf("[-] Error parsing HIBP response: %v", err).Println()
		return
	}

	// Display results
	Greenf("[+] Found %d breaches on Have I Been Pwned:\n", len(breaches)).Println()
	WriteToFile(username, fmt.Sprintf("[+] Found %d breaches on HIBP", len(breaches)))

	table := tablewriter.NewTable(os.Stdout)
	table.Header("No", "Breach", "Date", "Data Exposed")

	for i, breach := range breaches {
		dataTypes := strings.Join(breach.DataClasses, ", ")
		table.Append(i+1, Red(breach.Title), Yellow(breach.BreachDate), Cyan(dataTypes))
		WriteToFile(username, fmt.Sprintf("[+] Breach: %s | Date: %s | Data: %s", breach.Title, breach.BreachDate, dataTypes))
	}

	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}
}

// SearchLeakCheck searches LeakCheck.io for leaked credentials.
func SearchLeakCheck(username string, apikey string, wg *sync.WaitGroup) {
	defer wg.Done()

	Yellow("[*] Searching ", username, " on LeakCheck.io...").Println()
	WriteToFile(username, strings.Repeat("⎯", 85))
	WriteToFile(username, "[*] LeakCheck.io Results:")

	// Initialize HTTP client
	client := &http.Client{Timeout: 30 * time.Second}

	// Construct API URL
	url := fmt.Sprintf("https://leakcheck.io/api/public?check=%s", username)

	// Create request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		Redf("[-] Error creating LeakCheck request: %v", err).Println()
		return
	}

	// Set headers
	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("X-API-Key", apikey)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		Redf("[-] Error querying LeakCheck: %v", err).Println()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		Redf("[-] Invalid LeakCheck API key. Get one at: https://leakcheck.io/").Println()
		return
	}

	if resp.StatusCode != 200 {
		Redf("[-] LeakCheck returned status: %d", resp.StatusCode).Println()
		return
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Redf("[-] Error reading LeakCheck response: %v", err).Println()
		return
	}

	// Parse response
	var response LeakCheckResponse
	err = sonic.Unmarshal(body, &response)
	if err != nil {
		Redf("[-] Error parsing LeakCheck response: %v", err).Println()
		return
	}

	if response.Found == 0 {
		Red("[-] No leaks found for ", username, " on LeakCheck.").Println()
		WriteToFile(username, "[-] No leaks found on LeakCheck")
		return
	}

	// Display results
	Greenf("[+] Found %d leaks on LeakCheck.io:\n", response.Found).Println()
	WriteToFile(username, fmt.Sprintf("[+] Found %d leaks on LeakCheck", response.Found))

	table := tablewriter.NewTable(os.Stdout)
	table.Header("No", "Email/Username", "Password", "Sources")

	for i, result := range response.Result {
		identifier := result.Email
		if identifier == "" {
			identifier = result.Username
		}
		password := result.Password
		if password == "" {
			password = "[hashed/unavailable]"
		}
		sources := strings.Join(result.Sources, ", ")
		table.Append(i+1, Green(identifier), Red(password), Cyan(sources))
		WriteToFile(username, fmt.Sprintf("[+] %s | Password: %s | Sources: %s", identifier, password, sources))
	}

	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}
}

// SearchDeHashed searches DeHashed for leaked credentials.
func SearchDeHashed(username string, credentials string, wg *sync.WaitGroup) {
	defer wg.Done()

	Yellow("[*] Searching ", username, " on DeHashed...").Println()
	WriteToFile(username, strings.Repeat("⎯", 85))
	WriteToFile(username, "[*] DeHashed Results:")

	// Parse credentials (email:api_key format)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		Redf("[-] Invalid DeHashed credentials. Use format: email:api_key").Println()
		return
	}
	email := parts[0]
	apikey := parts[1]

	// Initialize HTTP client
	client := &http.Client{Timeout: 30 * time.Second}

	// Construct API URL
	url := fmt.Sprintf("https://api.dehashed.com/search?query=username:%s", username)

	// Create request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		Redf("[-] Error creating DeHashed request: %v", err).Println()
		return
	}

	// Set basic auth and headers
	req.SetBasicAuth(email, apikey)
	req.Header.Set("Accept", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		Redf("[-] Error querying DeHashed: %v", err).Println()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		Redf("[-] Invalid DeHashed credentials. Get API access at: https://dehashed.com/").Println()
		return
	}

	if resp.StatusCode != 200 {
		Redf("[-] DeHashed returned status: %d", resp.StatusCode).Println()
		return
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Redf("[-] Error reading DeHashed response: %v", err).Println()
		return
	}

	// Parse response
	var response DeHashedResponse
	err = sonic.Unmarshal(body, &response)
	if err != nil {
		Redf("[-] Error parsing DeHashed response: %v", err).Println()
		return
	}

	if response.Total == 0 {
		Red("[-] No results found for ", username, " on DeHashed.").Println()
		WriteToFile(username, "[-] No results found on DeHashed")
		return
	}

	// Display results
	Greenf("[+] Found %d results on DeHashed (Balance: %d credits):\n", response.Total, response.Balance).Println()
	WriteToFile(username, fmt.Sprintf("[+] Found %d results on DeHashed", response.Total))

	table := tablewriter.NewTable(os.Stdout)
	table.Header("No", "Email", "Username", "Password", "Database")

	for i, entry := range response.Entries {
		password := entry.Password
		if password == "" {
			password = entry.HashedPassword
			if password == "" {
				password = "[unavailable]"
			} else {
				password = "[hashed] " + password[:min(20, len(password))] + "..."
			}
		}
		table.Append(i+1, Green(entry.Email), Cyan(entry.Username), Red(password), Yellow(entry.Database))
		WriteToFile(username, fmt.Sprintf("[+] Email: %s | Username: %s | Password: %s | DB: %s", entry.Email, entry.Username, password, entry.Database))
	}

	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}
}

// SearchIntelX searches Intelligence X for leaks and pastes.
func SearchIntelX(username string, apikey string, wg *sync.WaitGroup) {
	defer wg.Done()

	Yellow("[*] Searching ", username, " on Intelligence X...").Println()
	WriteToFile(username, strings.Repeat("⎯", 85))
	WriteToFile(username, "[*] Intelligence X Results:")

	// Initialize HTTP client
	client := &http.Client{Timeout: 30 * time.Second}

	// Step 1: Create search
	searchPayload := fmt.Sprintf(`{"term":"%s","buckets":[],"lookuplevel":0,"maxresults":100,"timeout":0,"datefrom":"","dateto":"","sort":4,"media":0,"terminate":[]}`, username)

	req, err := http.NewRequest(http.MethodPost, "https://2.intelx.io/intelligent/search", strings.NewReader(searchPayload))
	if err != nil {
		Redf("[-] Error creating IntelX search request: %v", err).Println()
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Key", apikey)

	resp, err := client.Do(req)
	if err != nil {
		Redf("[-] Error querying IntelX: %v", err).Println()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		Redf("[-] Invalid IntelX API key. Get one at: https://intelx.io/").Println()
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Redf("[-] Error reading IntelX response: %v", err).Println()
		return
	}

	// Parse search ID
	var searchResult struct {
		ID string `json:"id"`
	}
	err = sonic.Unmarshal(body, &searchResult)
	if err != nil || searchResult.ID == "" {
		Redf("[-] Error initiating IntelX search: %v", err).Println()
		return
	}

	// Wait a moment for results to be ready
	time.Sleep(2 * time.Second)

	// Step 2: Get results
	resultsURL := fmt.Sprintf("https://2.intelx.io/intelligent/search/result?id=%s&limit=100", searchResult.ID)
	req2, err := http.NewRequest(http.MethodGet, resultsURL, nil)
	if err != nil {
		Redf("[-] Error creating IntelX results request: %v", err).Println()
		return
	}
	req2.Header.Set("X-Key", apikey)

	resp2, err := client.Do(req2)
	if err != nil {
		Redf("[-] Error fetching IntelX results: %v", err).Println()
		return
	}
	defer resp2.Body.Close()

	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		Redf("[-] Error reading IntelX results: %v", err).Println()
		return
	}

	// Parse results
	var response IntelXResponse
	err = sonic.Unmarshal(body2, &response)
	if err != nil {
		Redf("[-] Error parsing IntelX results: %v", err).Println()
		return
	}

	if len(response.Records) == 0 {
		Red("[-] No results found for ", username, " on Intelligence X.").Println()
		WriteToFile(username, "[-] No results found on Intelligence X")
		return
	}

	// Display results
	Greenf("[+] Found %d results on Intelligence X:\n", len(response.Records)).Println()
	WriteToFile(username, fmt.Sprintf("[+] Found %d results on IntelX", len(response.Records)))

	table := tablewriter.NewTable(os.Stdout)
	table.Header("No", "Name", "Date", "Source")

	for i, record := range response.Records {
		table.Append(i+1, Green(record.Name), Yellow(record.Date), Cyan(record.Bucket))
		WriteToFile(username, fmt.Sprintf("[+] Name: %s | Date: %s | Source: %s", record.Name, record.Date, record.Bucket))
	}

	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}
}

// SearchGitHubCode searches GitHub for potentially leaked credentials in public repos.
func SearchGitHubCode(username string, token string, wg *sync.WaitGroup) {
	defer wg.Done()

	Yellow("[*] Searching GitHub for leaked credentials containing ", username, "...").Println()
	WriteToFile(username, strings.Repeat("⎯", 85))
	WriteToFile(username, "[*] GitHub Code Search Results:")

	// Initialize HTTP client
	client := &http.Client{Timeout: 30 * time.Second}

	// Search queries to find potential credential leaks
	queries := []string{
		fmt.Sprintf(`"%s" password`, username),
		fmt.Sprintf(`"%s" secret`, username),
		fmt.Sprintf(`"%s" api_key`, username),
		fmt.Sprintf(`"%s" token`, username),
	}

	var allResults []GitHubCodeSearchItem

	for _, query := range queries {
		// URL encode the query
		encodedQuery := strings.ReplaceAll(query, " ", "+")
		encodedQuery = strings.ReplaceAll(encodedQuery, `"`, "%22")

		url := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=10", encodedQuery)

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("User-Agent", "GoSearch-OSINT")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 403 {
			Yellow("[!] GitHub rate limit reached. Try again later.").Println()
			resp.Body.Close()
			break
		}

		if resp.StatusCode == 401 {
			Redf("[-] Invalid GitHub token.").Println()
			resp.Body.Close()
			return
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var searchResp GitHubCodeSearchResponse
		err = sonic.Unmarshal(body, &searchResp)
		if err != nil {
			continue
		}

		allResults = append(allResults, searchResp.Items...)

		// Rate limit: wait between queries
		time.Sleep(2 * time.Second)
	}

	if len(allResults) == 0 {
		Red("[-] No potential credential leaks found for ", username, " on GitHub.").Println()
		WriteToFile(username, "[-] No credential leaks found on GitHub")
		return
	}

	// Deduplicate results by URL
	seen := make(map[string]bool)
	var uniqueResults []GitHubCodeSearchItem
	for _, item := range allResults {
		if !seen[item.HTMLURL] {
			seen[item.HTMLURL] = true
			uniqueResults = append(uniqueResults, item)
		}
	}

	Greenf("[+] Found %d potential credential exposures on GitHub:\n", len(uniqueResults)).Println()
	Yellow("[!] WARNING: Review these manually - may contain false positives").Println()
	WriteToFile(username, fmt.Sprintf("[+] Found %d potential exposures on GitHub", len(uniqueResults)))

	table := tablewriter.NewTable(os.Stdout)
	table.Header("No", "Repository", "File", "URL")

	for i, item := range uniqueResults {
		if i >= 20 { // Limit display to 20 results
			Yellowf("[...] %d more results not shown", len(uniqueResults)-20).Println()
			break
		}
		table.Append(i+1, Cyan(item.Repository.FullName), Yellow(item.Name), Green(item.HTMLURL))
		WriteToFile(username, fmt.Sprintf("[+] Repo: %s | File: %s | URL: %s", item.Repository.FullName, item.Name, item.HTMLURL))
	}

	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}
}

// CrackHash attempts to crack a password hash using the Weakpass API.
func CrackHash(hash string) string {
	// Initialize HTTP client
	client := &http.Client{}
	// Construct API URL
	url := fmt.Sprintf("https://weakpass.com/api/v1/search/%s.json", hash)

	// Create request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function CrackHash: %v\n", err)
		return ""
	}

	// Set request headers
	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("accept:", "application/json")

	// Send request
	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error fetching response in function CrackHash: %v\n", err)
		return ""
	}
	defer res.Body.Close()

	// Read response body
	jsonData, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error reading response JSON: %v\n", err)
		return ""
	}

	// Parse JSON response
	var weakpass WeakpassResponse
	err = sonic.Unmarshal(jsonData, &weakpass)
	if err != nil {
		fmt.Printf("Error unmarshalling JSON: %v\n", err)
		return ""
	}
	// Return cracked password
	return weakpass.Pass
}

// MakeRequestWithResponseURL checks for profile existence by comparing the response URL.
func MakeRequestWithResponseURL(website Website, url string, username string) {
	// Some websites always return a 200 for existing and non-existing profiles.
	// If we do not follow redirects, we could get a 301 for existing profiles and 302 for non-existing profiles.
	// That is why we have the follow_redirects in our website struct.
	// However, sometimes the website returns 301 for existing profiles and non-existing profiles.
	// This means even if we do not follow redirects, we still get false positives.
	// To mitigate this, we can examine the response url to check for non-existing profiles.
	// Usually, a response url pointing to where the profile should be is returned for existing profiles.
	// If the response url is not pointing to where the profile should be, then the profile does not exist.

	// Initialize HTTP client with timeout and transport settings
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

	// Disable redirects if specified
	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Set User-Agent
	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	// Create request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithResponseURL: %v\n", err)
		return
	}

	// Set request headers
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

	// Add cookies if specified
	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
	}

	// Send request
	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	// Check for error status codes
	if res.StatusCode >= 400 {
		return
	}

	// Compare response URL with expected URL
	formattedResponseURL := BuildURL(website.ResponseURL, username)
	if !(res.Request.URL.String() == formattedResponseURL) {
		url = BuildURL(website.BaseURL, username)
		Green("[+]", website.Name, ":", url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

// MakeRequestWithErrorCode checks for profile existence by comparing HTTP status codes.
func MakeRequestWithErrorCode(website Website, url string, username string) {
	// Initialize HTTP client
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

	// Disable redirects if specified
	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Set User-Agent
	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	// Create request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorCode: %v\n", err)
		return
	}

	// Set request headers
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

	// Add cookies if specified
	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
	}

	// Send request
	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	// Check for error status codes
	if res.StatusCode >= 400 {
		return
	}

	// Check if status code differs from error code
	if res.StatusCode != website.ErrorCode {
		url = BuildURL(website.BaseURL, username)
		Green("[+] ", website.Name, ":", url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

// MakeRequestWithErrorMsg checks for profile existence by searching for an error message in the response body.
func MakeRequestWithErrorMsg(website Website, url string, username string) {
	// Initialize HTTP client
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

	// Disable redirects if specified
	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Set User-Agent
	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	// Create request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorMsg: %v\n", err)
		return
	}

	// Set request headers
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

	// Add cookies if specified
	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
	}

	// Send request
	res, err := client.Do(req)
	if err != nil {
		return
	}
	// Handle response body compression
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

	// Check for error status codes
	if res.StatusCode >= 400 {
		return
	}

	// Read response body
	body, err := io.ReadAll(reader)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	// Check for error message
	bodyStr := string(body)
	if !strings.Contains(bodyStr, website.ErrorMsg) {
		url = BuildURL(website.BaseURL, username)
		Green("[+] ", website.Name, ":", url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

// MakeRequestWithProfilePresence checks for profile existence by searching for a profile indicator in the response body.
func MakeRequestWithProfilePresence(website Website, url string, username string) {
	// Some websites have an indicator that a profile exists
	// but do not have an indicator when a profile does not exist.
	// If a profile indicator is not found, we can assume that the profile does not exist.

	// Initialize HTTP client
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

	// Disable redirects if specified
	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Set User-Agent
	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	// Create request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorMsg: %v\n", err)
		return
	}

	// Set request headers
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

	// Add cookies if specified
	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
	}

	// Send request
	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	// Check for error status codes
	if res.StatusCode >= 400 {
		return
	}

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	// Check for profile indicator
	bodyStr := string(body)
	if strings.Contains(bodyStr, website.ErrorMsg) {
		Greenf("[+] %s: %s", website.Name, url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

// Search performs concurrent searches across all configured websites.
func Search(data Data, username string, noFalsePositives bool, wg *sync.WaitGroup) {
	// Iterate over websites
	for _, website := range data.Websites {
		// Run search in a goroutine
		go func(website Website) {
			var url string
			defer wg.Done()

			// Use probe URL if specified, otherwise use base URL
			if website.URLProbe != "" {
				url = BuildURL(website.URLProbe, username)
			} else {
				url = BuildURL(website.BaseURL, username)
			}

			// Handle different error types
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
				// Handle unverified profiles if false positives are allowed
				if !noFalsePositives {
					Yellowf("[?] %s: %s", website.Name, url).Println()
					WriteToFile(username, "[?] "+url+"\n")
					count.Add(1)
				}
			}
		}(website)
	}
}

// DeleteOldFile removes any existing output file for the username.
func DeleteOldFile(username string) {
	filename := fmt.Sprintf("%s.txt", username)
	os.Remove(filename)
}

// Text creates a colored string using the specified color code.
func Text(s string, colorCode string) Color {
	return Color(colorCode + s + CurrentTheme.Reset)
}

// Red formats text in red.
func Red(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Red)
}

// Green formats text in green.
func Green(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Green)
}

// Yellow formats text in yellow.
func Yellow(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Yellow)
}

// Blue formats text in blue.
func Blue(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Blue)
}

// Cyan formats text in cyan.
func Cyan(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Cyan)
}

// Magenta formats text in magenta.
func Magenta(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Magenta)
}

// White formats text in white.
func White(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.White)
}

// Gray formats text in gray.
func Gray(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Gray)
}

// Redf formats text in red with a format string.
func Redf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Red)
}

// Greenf formats text in green with a format string.
func Greenf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Green)
}

// Yellowf formats text in yellow with a format string.
func Yellowf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Yellow)
}

// Bluef formats text in blue with a format string.
func Bluef(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Blue)
}

// Cyanf formats text in cyan with a format string.
func Cyanf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Cyan)
}

// Magentaf formats text in magenta with a format string.
func Magentaf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Magenta)
}

// Whitef formats text in white with a format string.
func Whitef(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.White)
}

// Grayf formats text in gray with a format string.
func Grayf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Gray)
}

// Bold formats text in bold.
func Bold(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Bold)
}

// formatStealerDate formats a date string from HudsonRock API into a human-readable format.
func formatStealerDate(dateStr string) string {
	// Parse the HudsonRock API date format (e.g., "2025-05-15T05:43:36.000Z")
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return dateStr // Return original if parsing fails
	}

	// Format as relative time if recent, absolute date if older
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

// plural returns an empty string for singular or "s" for plural.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// detectTheme determines the terminal color theme based on the COLORFGBG environment variable.
func detectTheme() Theme {
	colorfgbg := os.Getenv("COLORFGBG")
	if strings.Contains(colorfgbg, ";0") {
		return DarkTheme // Dark background
	} else if strings.Contains(colorfgbg, ";15") {
		return LightTheme // Light background
	}
	return DarkTheme // Default
}
