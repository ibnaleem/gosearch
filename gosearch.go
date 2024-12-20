package gosearch

import (
	"fmt"
	"io"
	"os"
	"log"
	"time"
	"sync"
	"strings"
	"net/http"
	"crypto/tls"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"github.com/inancgumus/screen"
	"github.com/ibnaleem/gobreach"
)

var Red = "\033[31m" 
var Reset = "\033[0m"
var Green = "\033[32m"
var Yellow = "\033[33m"
var ASCII string = `
 ________  ________  ________  _______   ________  ________  ________  ___  ___     
|\   ____\|\   __  \|\   ____\|\  ___ \ |\   __  \|\   __  \|\   ____\|\  \|\  \    
\ \  \___|\ \  \|\  \ \  \___|\ \   __/|\ \  \|\  \ \  \|\  \ \  \___|\ \  \\\  \   
 \ \  \  __\ \  \\\  \ \_____  \ \  \_|/_\ \   __  \ \   _  _\ \  \    \ \   __  \  
  \ \  \|\  \ \  \\\  \|____|\  \ \  \_|\ \ \  \ \  \ \  \\  \\ \  \____\ \  \ \  \ 
   \ \_______\ \_______\____\_\  \ \_______\ \__\ \__\ \__\\ _\\ \_______\ \__\ \__\
    \|_______|\|_______|\_________\|_______|\|__|\|__|\|__|\|__|\|_______|\|__|\|__|
                       \|_________|
`
var VERSION string = "v1.0.0"
var count uint16 = 0 // Maximum value for count is 65,535

type Website struct {
	Name             string   `yaml:"name"`
	BaseURL          string   `yaml:"base_url"`
	URLProbe         string   `yaml:"url_probe,omitempty"`
	FollowRedirects  bool     `yaml:"follow_redirects,omitempty"`
	ErrorType        string   `yaml:"errorType"`
	ErrorMsg         string   `yaml:"errorMsg,omitempty"`
	ErrorCode        int      `yaml:"errorCode,omitempty"`
	Cookies          []Cookie `yaml:"cookies,omitempty"`
}

type Config struct {
	Websites []Website `yaml:"websites"`
}

type Cookie struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type Stealer struct {
	TotalCorporateServices int      `json:"total_corporate_services"`
	TotalUserServices      int      `json:"total_user_services"`
	DateCompromised        string   `json:"date_compromised"`
	StealerFamily          string   `json:"stealer_family"`
	ComputerName           string   `json:"computer_name"`
	OperatingSystem        string   `json:"operating_system"`
	MalwarePath            string   `json:"malware_path"`
	Antiviruses            interface{} `json:"antiviruses"`
	IP                     string   `json:"ip"`
	TopPasswords           []string `json:"top_passwords"`
	TopLogins              []string `json:"top_logins"`
}

type HudsonRockResponse struct {
	Message string    `json:"message"`
	Stealers []Stealer `json:"stealers"`
}

func UnmarshalYAML() (Config, error) {

	// GoSearch relies on config.yaml to determine the websites to search for.
	// Instead of forcing uers to manually download the config.yaml file, we will fetch the latest version from the repository.
	// Thereforeore, we will do the following:
	// 1. Delete the existing config.yaml file if it exists as it will be outdated in the future
	// 2. Read the latest config.yaml file from the repository
	// Bonus: it does not download the config.yaml file, it just reads it from the repository.

	err := os.Remove("config.yaml")
	if err != nil && !os.IsNotExist(err) {
		return Config{}, fmt.Errorf("error deleting old config.yaml: %w", err)
	}

	url := "https://raw.githubusercontent.com/ibnaleem/gosearch/refs/heads/main/config.yaml"
	resp, err := http.Get(url)
	if err != nil {
		return Config{}, fmt.Errorf("error downloading config.yaml: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Config{}, fmt.Errorf("failed to download config.yaml, status code: %d", resp.StatusCode)
	}

	yamlData, err := io.ReadAll(resp.Body)
	if err != nil {
		return Config{}, fmt.Errorf("error reading downloaded content: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(yamlData, &config)
	if err != nil {
		return Config{}, fmt.Errorf("error unmarshaling YAML: %w", err)
	}

	return config, nil
}

func WriteToFile(username string, content string) {

	filename := fmt.Sprintf("%s.txt", username)

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if _, err = f.WriteString(content); err != nil {
		panic(err)
	}
}

func BuildURL(baseURL, username string) string {
	return strings.Replace(baseURL, "{}", username, 1)
}

func HudsonRock(username string, wg *sync.WaitGroup) {

	defer wg.Done()

	url := "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=" + username

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching data for " + username + " in HudsonRock function:", err)
		return
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response in HudsonRock function:", err)
		return
	}

	var response HudsonRockResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error parsing JSON in HudsonRock function:", err)
		return
	}

	if response.Message == "This username is not associated with a computer infected by an info-stealer. Visit https://www.hudsonrock.com/free-tools to discover additional free tools and Infostealers related data." {
		fmt.Println(Green + ":: This username is not associated with a computer infected by an info-stealer." + Reset)
		WriteToFile(username, ":: This username is not associated with a computer infected by an info-stealer.")
		return
	} else {
		fmt.Println(Red + ":: This username is associated with a computer that was infected by an info-stealer, all the credentials saved on this computer are at risk of being accessed by cybercriminals." + Reset)

		for i, stealer := range response.Stealers {
			fmt.Println(Red + fmt.Sprintf("[-] Stealer #%d", i+1) + Reset)
			fmt.Println(Red + fmt.Sprintf("::  Stealer Family: %s", stealer.StealerFamily) + Reset)
			fmt.Println(Red + fmt.Sprintf("::  Date Compromised: %s", stealer.DateCompromised) + Reset)
			fmt.Println(Red + fmt.Sprintf("::  Computer Name: %s", stealer.ComputerName) + Reset)
			fmt.Println(Red + fmt.Sprintf(":: Operating System: %s", stealer.OperatingSystem) + Reset)
			fmt.Println(Red + fmt.Sprintf("::  Malware Path: %s", stealer.MalwarePath) + Reset)
			
			switch v := stealer.Antiviruses.(type) {
			case string:
				fmt.Println(Red + fmt.Sprintf(":: Antiviruses: %s", v) + Reset)
			case []interface{}:
				antiviruses := ""
				for _, av := range v {
					antiviruses += fmt.Sprintf("%s, ", av)
				}
				fmt.Println(Red + fmt.Sprintf("::  Antiviruses: %s", antiviruses[:len(antiviruses)-2]) + Reset)
			}
			

			fmt.Println(Red + fmt.Sprintf("::  IP: %s", stealer.IP) + Reset)

			fmt.Println(Red + "[-] Top Passwords:" + Reset)
			for _, password := range stealer.TopPasswords {
				fmt.Println(Red + fmt.Sprintf("::    %s", password) + Reset)
			}

			fmt.Println(Red + "[-] Top Logins:" + Reset)
			for _, login := range stealer.TopLogins {
				fmt.Println(Red + fmt.Sprintf("::    %s", login) + Reset)
			}
		}

		// For performance reasons, we should not print and write to the file at the same time during a single for-loop interation.
		// Therefore, there will be 2 for-loop interations: one for printing, and one for writing to the file.
		// This ensures that GoSearch can print as quickkly as possible since the terminal output is most important.

		for i, stealer := range response.Stealers {
			WriteToFile(username, fmt.Sprintf("[-] Stealer #%d", i+1))
			WriteToFile(username, fmt.Sprintf("\n::  Stealer Family: %s", stealer.StealerFamily + "\n"))
			WriteToFile(username, fmt.Sprintf("::  Date Compromised: %s", stealer.DateCompromised + "\n"))
			WriteToFile(username, fmt.Sprintf("::  Computer Name: %s", stealer.ComputerName + "\n"))
			WriteToFile(username, fmt.Sprintf(":: Operating System: %s", stealer.OperatingSystem + "\n"))
			WriteToFile(username, fmt.Sprintf("::  Malware Path: %s", stealer.MalwarePath + "\n"))
			
			switch v := stealer.Antiviruses.(type) {
			case string:
				WriteToFile(username, fmt.Sprintf(":: Antiviruses: %s", v + "\n"))
			case []interface{}:
				antiviruses := ""
				for _, av := range v {
					antiviruses += fmt.Sprintf("%s, ", av)
				}
				WriteToFile(username, fmt.Sprintf("::  Antiviruses: %s", antiviruses[:len(antiviruses)-2] + "\n"))
			}
			
			WriteToFile(username, fmt.Sprintf("::  IP: %s", stealer.IP + "\n"))

			WriteToFile(username, "[-] Top Passwords:")
			for _, password := range stealer.TopPasswords {
				WriteToFile(username, fmt.Sprintf("::    %s", password + "\n"))
			}

			WriteToFile(username, "[-] Top Logins:")
			for _, login := range stealer.TopLogins {
				WriteToFile(username, fmt.Sprintf("::    %s", login + "\n"))
			}
		}
	}
}


func BuildEmail(username string) []string {
	emailDomains := []string{
			"@gmail.com",
			"@yahoo.com",
			"@outlook.com",
			"@hotmail.com",
			"@icloud.com",
			"@aol.com",
			"@live.com",
			"@protonmail.com",
			"@zoho.com",
			"@msn.com",
			"proton.me",
			"onionmail.org",
			"gmx.de",
			"mail2world.com",
	}

	var emails []string

	for _, domain := range emailDomains {
			emails = append(emails, username + domain)
	}

	return emails
}

func SearchBreachDirectory(emails []string, apikey string, wg *sync.WaitGroup) {

	defer wg.Done()

	// Get an API key (10 lookups for free) @ https://rapidapi.com/rohan-patra/api/breachdirectory
	client, err := gobreach.NewBreachDirectoryClient(apikey)
	
	if err != nil {
		log.Fatal(err)
	}

	for _, email := range emails {

		fmt.Println(Yellow + "[*] Searching " + email + " on Breach Directory for any compromised passwords..." + Reset)
		
		response, err := client.SearchEmail(email)
		if err != nil {
			log.Fatal(err)
		}

		if response.Found > 0 {
			fmt.Printf(Green + "[+] Found %d breaches for %s:\n", response.Found, email + Reset)
			for _, entry := range response.Result {
				fmt.Println(Green + "[+] Password:", entry.Password + Reset)
				fmt.Println(Green + "[+] SHA1:", entry.Sha1 + Reset)
				fmt.Println(Green + "[+] Source:", entry.Sources + Reset)
			}
		} else {
			fmt.Printf(Red + "[-] No breaches found for %s. Moving on...\n", email + Reset)
		}
	}
}

func MakeRequestWithErrorCode(website Website, url string, username string) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	client := &http.Client{
		Timeout:   85 * time.Second,
		Transport: transport,
	}

	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorCode: %v\n", err)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0")

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
		fmt.Printf("Error making GET request to %s: %v\n", url, err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != website.ErrorCode {
		fmt.Println(Green + "[+]", website.Name + ":", url + Reset)
		WriteToFile(username, url + "\n")
		count++
	}
}

func MakeRequestWithErrorMsg(website Website, url string, username string) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	client := &http.Client{
		Timeout:   85 * time.Second,
		Transport: transport,
	}

	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorMsg: %v\n", err)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0")

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
		fmt.Printf("Error making GET request to %s: %v\n", url, err)
		return
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	if website.URLProbe != "" {
		url = BuildURL(website.BaseURL, username)
	}

	bodyStr := string(body)
	// if the error message is not found in the response body, then the profile exists
	if !strings.Contains(bodyStr, website.ErrorMsg) {
		fmt.Println(Green + "[+]", website.Name + ":", url + Reset)
		WriteToFile(username, url + "\n")
		count++
	}
}

func MakeRequestWithProfilePresence(website Website, url string, username string) {

	// Some websites have an indicator that a profile exists
	// but do not have an indicator when a profile does not exist.
	// If a profile indicator is not found, we can assume that the profile does not exist.

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	client := &http.Client{
		Timeout:   85 * time.Second,
		Transport: transport,
	}

	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorMsg: %v\n", err)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0")

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
		fmt.Printf("Error making GET request to %s: %v\n", url, err)
		return
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	if website.URLProbe != "" {
		url = BuildURL(website.BaseURL, username)
	}

	bodyStr := string(body)
	// if the profile indicator is found in the response body, the profile exists
	if strings.Contains(bodyStr, website.ErrorMsg) { 
		fmt.Println(Green + "[+]", website.Name + ":", url + Reset)
		WriteToFile(username, url + "\n")
		count++
	}

}
func Search(config Config, username string, wg *sync.WaitGroup) {
	var url string

	for _, website := range config.Websites {
		go func(website Website) {
			defer wg.Done()

			if website.URLProbe != "" {
				url = BuildURL(website.URLProbe, username)
			} else {
				url = BuildURL(website.BaseURL, username)
			}

			if website.ErrorType == "status_code" {
				MakeRequestWithErrorCode(website, url, username)
			} else if website.ErrorType == "errorMsg" {				
				MakeRequestWithErrorMsg(website, url, username)
			} else if website.ErrorType == "profilePresence" {				
				MakeRequestWithProfilePresence(website, url, username)
			} else {
				fmt.Println(Yellow + "[?]", website.Name + ":", url + Reset)
                WriteToFile(username, "[?] " + url + "\n")
				count++
			}
		}(website)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: gosearch <username>\nIssues: https://github.com/ibnaleem/gosearch/issues")
		os.Exit(1)
	}

	var username string = os.Args[1]
	var wg sync.WaitGroup

	config, err := UnmarshalYAML()
	if err != nil {
		fmt.Printf("Error unmarshaling YAML: %v\n", err)
		os.Exit(1)
	}

	screen.Clear()
	fmt.Println(ASCII)
	fmt.Println(VERSION)
	fmt.Println(strings.Repeat("⎯", 85))
	fmt.Println(":: Username                              : ", username)
	fmt.Println(":: Websites                              : ", len(config.Websites))
	fmt.Println(strings.Repeat("⎯", 85))
	fmt.Println("[!] A yellow link indicates that I was unable to verify whether the username exists on the platform.")

	start := time.Now()

	wg.Add(len(config.Websites))
	go Search(config, username, &wg)
	wg.Wait()

	wg.Add(1)
	fmt.Println(strings.Repeat("⎯", 85))
	fmt.Println(Yellow + "[*] Searching HudsonRock's Cybercrime Intelligence Database..." + Reset)
	go HudsonRock(username, &wg)
	wg.Wait()


	if len(os.Args) == 3 {
		apikey := os.Args[2]
		fmt.Println(strings.Repeat("⎯", 85))
		emails := BuildEmail(username)
    wg.Add(1)
    go SearchBreachDirectory(emails, apikey, &wg)
    wg.Wait()
  }

	elapsed := time.Since(start)
	fmt.Println(strings.Repeat("⎯", 85))
	fmt.Println(":: Number of profiles found              : ", count)
	fmt.Println(":: Total time taken                      : ", elapsed)
	
	os.Exit(0)
}
