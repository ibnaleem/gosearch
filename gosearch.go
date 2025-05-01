package main

import (
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/bytedance/sonic"
	"github.com/ibnaleem/gobreach"
	"github.com/inancgumus/screen"
)

// Color output constants.
const (
	Red    = "\033[31m"
	Reset  = "\033[0m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
)

// GoSearch ASCII logo.
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

// User-Agent header used in requests.
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"

// GoSearch version.
const VERSION = "v1.0.0"

var tlsConfig = &tls.Config{
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

var count atomic.Uint32

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

func UnmarshalJSON() (Data, error) {
	// GoSearch relies on data.json to determine the websites to search for.
	// Instead of forcing users to manually download the data.json file, we will fetch the latest version from the repository.
	// Therefore, we will do the following:
	// 1. Delete the existing data.json file if it exists as it will be outdated in the future
	// 2. Read the latest data.json file from the repository
	// Bonus: it does not download the data.json file, it just reads it from the repository.

	err := os.Remove("data.json")
	if err != nil && !os.IsNotExist(err) {
		return Data{}, fmt.Errorf("error deleting old data.json: %w", err)
	}

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
	filename := fmt.Sprintf("%s.txt", username)

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModePerm)
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

	url := "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=" + username

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching data for "+username+" in HudsonRock function:", err)
		return
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response in HudsonRock function:", err)
		return
	}

	var response HudsonRockResponse
	err = sonic.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error parsing JSON in HudsonRock function:", err)
		return
	}

	if response.Message == "This username is not associated with a computer infected by an info-stealer. Visit https://www.hudsonrock.com/free-tools to discover additional free tools and Infostealers related data." {
		fmt.Println(Green + ":: This username is not associated with a computer infected by an info-stealer." + Reset)
		WriteToFile(username, ":: This username is not associated with a computer infected by an info-stealer.")
		return
	}

	fmt.Println(Red + ":: This username is associated with a computer that was infected by an info-stealer, all the credentials saved on this computer are at risk of being accessed by cybercriminals." + Reset)

	for i, stealer := range response.Stealers {
		fmt.Println(Red + fmt.Sprintf("[-] Stealer #%d", i+1) + Reset)
		fmt.Println(Red + fmt.Sprintf("::    Stealer Family: %s", stealer.StealerFamily) + Reset)
		fmt.Println(Red + fmt.Sprintf("::    Date Compromised: %s", stealer.DateCompromised) + Reset)
		fmt.Println(Red + fmt.Sprintf("::    Computer Name: %s", stealer.ComputerName) + Reset)
		fmt.Println(Red + fmt.Sprintf("::    Operating System: %s", stealer.OperatingSystem) + Reset)
		fmt.Println(Red + fmt.Sprintf("::    Malware Path: %s", stealer.MalwarePath) + Reset)

		switch v := stealer.Antiviruses.(type) {
		case string:
			WriteToFile(username, fmt.Sprintf("::    Antiviruses: %s\n", v))
		case []interface{}:
			antiviruses := make([]string, len(v))

			for i, av := range v {
				antiviruses[i] = fmt.Sprint(av)
			}

			avs := strings.Join(antiviruses, ", ")
			WriteToFile(username, fmt.Sprintf("::    Antiviruses: %s\n", avs))
		}

		fmt.Println(Red + fmt.Sprintf("::    IP: %s", stealer.IP) + Reset)

		fmt.Println(Red + "[-] Top Passwords:" + Reset)
		for _, password := range stealer.TopPasswords {
			fmt.Println(Red + fmt.Sprintf("::    %s", password) + Reset)
		}

		fmt.Println(Red + "[-] Top Logins:" + Reset)
		for _, login := range stealer.TopLogins {
			fmt.Println(Red + fmt.Sprintf("::    %s", login) + Reset)
		}
	}

	// For performance reasons, we should not print and write to the file at the same time during a single for-loop iteration.
	// Therefore, there will be 2 for-loop iterations: one for printing, and one for writing to the file.
	// This ensures that GoSearch can print as quickly as possible since the terminal output is most important.

	for i, stealer := range response.Stealers {
		WriteToFile(username, fmt.Sprintf("[-] Stealer #%d\n", i+1))
		WriteToFile(username, fmt.Sprintf("::    Stealer Family: %s\n", stealer.StealerFamily))
		WriteToFile(username, fmt.Sprintf("::    Date Compromised: %s\n", stealer.DateCompromised))
		WriteToFile(username, fmt.Sprintf("::    Computer Name: %s\n", stealer.ComputerName))
		WriteToFile(username, fmt.Sprintf("::    Operating System: %s\n", stealer.OperatingSystem))
		WriteToFile(username, fmt.Sprintf("::    Malware Path: %s\n", stealer.MalwarePath))

		switch v := stealer.Antiviruses.(type) {
		case string:
			WriteToFile(username, fmt.Sprintf("::    Antiviruses: %s\n", v))
		case []interface{}:
			antiviruses := make([]string, len(v))

			for i, av := range v {
				antiviruses[i] = fmt.Sprint(av)
			}

			avs := strings.Join(antiviruses, ", ")
			WriteToFile(username, fmt.Sprintf("::    Antiviruses: %s\n", avs))
		}

		WriteToFile(username, fmt.Sprintf("::    IP: %s\n", stealer.IP))

		WriteToFile(username, "[-] Top Passwords:\n")
		for _, password := range stealer.TopPasswords {
			WriteToFile(username, fmt.Sprintf("::    %s\n", password))
		}

		WriteToFile(username, "[-] Top Logins:\n")
		for _, login := range stealer.TopLogins {
			WriteToFile(username, fmt.Sprintf("::    %s\n", login))
		}
	}
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
	fmt.Println(Yellow+"[*] Searching", len(domains), "domains with the username", username, "..."+Reset)

	domaincount := 0

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
			netErr, ok := err.(net.Error)

			// The following errors mean that the domain does not exist.
			noSuchHostError := strings.Contains(err.Error(), "no such host")
			networkTimeoutError := ok && netErr.Timeout()

			if !noSuchHostError && !networkTimeoutError {
				fmt.Printf("Error sending request for %s: %v\n", domain, err)
			}

			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			fmt.Println(Green+"[+] 200 OK:", domain+Reset)
			WriteToFile(username, "[+] 200 OK: "+domain)
			domaincount++
		}
	}

	if domaincount > 0 {
		fmt.Println(Green+"[+] Found", domaincount, "domains with the username", username+Reset)
		WriteToFile(username, "[+] Found "+strconv.Itoa(domaincount)+" domains with the username: "+username)
	} else {
		fmt.Println(Red+"[-] No domains found with the username", username+Reset)
		WriteToFile(username, "[-] No domains found with the username: "+username)
	}
}

func SearchProxyNova(username string, wg *sync.WaitGroup) {

	defer wg.Done()

	fmt.Println(Yellow + "[*] Searching " + username + " on ProxyNova for any compromised passwords..." + Reset)

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
		fmt.Printf(Green+"[+] Found %d compromised passwords for %s:\n", response.Count, username+Reset)
		for _, element := range response.Lines {
			parts := strings.Split(element, ":")

			if len(parts) == 2 {
				email := parts[0]
				password := parts[1]

				fmt.Printf(Green+"::    Email: %s\n", email+Reset)
				fmt.Printf(Green+"::    Password: %s\n\n", password+Reset)

				WriteToFile(username, "[+] Email: "+email+"\n"+"[+] Password: "+password+"\n\n")
			}
		}
	} else {
		fmt.Println(Red + "[-] No compromised passwords found for " + username + "." + Reset)
	}
}

func SearchBreachDirectory(username string, apikey string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Get an API key (10 lookups for free) @ https://rapidapi.com/rohan-patra/api/breachdirectory
	client, err := gobreach.NewBreachDirectoryClient(apikey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(Yellow + "[*] Searching " + username + " on Breach Directory for any compromised passwords..." + Reset)

	response, err := client.Search(username)
	if err != nil {
		log.Fatal(err)
	}

	if response.Found == 0 {
		fmt.Printf(Red+"[-] No breaches found for %s.", username+Reset)
		WriteToFile(username, "[-] No breaches found on Breach Directory for: "+username)
	}

	fmt.Printf(Green+"[+] Found %d breaches for %s:\n", response.Found, username+Reset)
	for _, entry := range response.Result {

		pass := CrackHash(entry.Hash)
		if pass != "" {
			fmt.Println(Green+"[+] Password:", pass+Reset)
			WriteToFile(username, "[+] Password: "+pass)
		} else {
			fmt.Println(Green+"[+] Password:", entry.Password+Reset)
			WriteToFile(username, "[+] Password: "+entry.Password)
		}

		fmt.Println(Green+"[+] SHA1:", entry.Sha1+Reset)
		fmt.Println(Green+"[+] Source:", entry.Sources+Reset)
		fmt.Println(Green+"[+] SHA1:", entry.Sha1)
		WriteToFile(username, "[+] Source: "+entry.Sources)
	}
}

func CrackHash(hash string) string {
	// We will crack the hash from BreachDirectory using Weakpass

	client := &http.Client{}
	url := fmt.Sprintf("https://weakpass.com/api/v1/search/%s.json", hash)

	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		fmt.Printf("Error creating request in function CrackHash: %v\n", err)
		return ""
	}

	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("accept:", "application/json")

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
		fmt.Println(Green+"[+]", website.Name+":", url+Reset)
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
		fmt.Println(Green+"[+]", website.Name+":", url+Reset)
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
		reader, err = gzip.NewReader(res.Body)
	case "deflate":
		reader, err = zlib.NewReader(res.Body)
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
	// if the error message is not found in the response body, then the profile exists
	if !strings.Contains(bodyStr, website.ErrorMsg) {
		url = BuildURL(website.BaseURL, username)
		fmt.Println(Green+"[+]", website.Name+":", url+Reset)
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
	// if the profile indicator is found in the response body, the profile exists
	if strings.Contains(bodyStr, website.ErrorMsg) {
		fmt.Println(Green+"[+]", website.Name+":", url+Reset)
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
				// if false positives are disabled, then we can print false positives
				if !noFalsePositives {
					fmt.Println(Yellow+"[?]", website.Name+":", url+Reset)
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

func main() {

	var username string
	var apikey string

	usernameFlag := flag.String("u", "", "Username to search")
	usernameFlagLong := flag.String("username", "", "Username to search")
	noFalsePositivesFlag := flag.Bool("no-false-positives", false, "Do not show false positives")
	breachDirectoryAPIKey := flag.String("b", "", "Search Breach Directory with an API Key")
	breachDirectoryAPIKeyLong := flag.String("breach-directory", "", "Search Breach Directory with an API Key")

	flag.Parse()

	if *usernameFlag != "" {
		username = *usernameFlag
	} else if *usernameFlagLong != "" {
		username = *usernameFlagLong
	} else {
		if len(os.Args) > 1 {
			username = os.Args[1]
		} else {
			fmt.Println("Usage: gosearch -u <username>\nIssues: https://github.com/ibnaleem/gosearch/issues")
			os.Exit(1)
		}
	}

	DeleteOldFile(username)
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

	// if the false positive flag is true, then specify that false positives are not shown
	if *noFalsePositivesFlag {
		fmt.Println(":: No False Positives                    : ", *noFalsePositivesFlag)
	}

	fmt.Println(strings.Repeat("⎯", 85))

	// if the false positive flag is not set, then show a message
	if !*noFalsePositivesFlag {
		fmt.Println("[!] A yellow link indicates that I was unable to verify whether the username exists on the platform.")
	}

	start := time.Now()

	wg.Add(len(data.Websites))
	go Search(data, username, *noFalsePositivesFlag, &wg)
	wg.Wait()

	wg.Add(1)
	fmt.Println(strings.Repeat("⎯", 85))
	WriteToFile(username, strings.Repeat("⎯", 85))
	fmt.Println(Yellow + "[*] Searching HudsonRock's Cybercrime Intelligence Database..." + Reset)
	go HudsonRock(username, &wg)
	wg.Wait()

	if *breachDirectoryAPIKey != "" || *breachDirectoryAPIKeyLong != "" {
		if *breachDirectoryAPIKey != "" {
			apikey = *breachDirectoryAPIKey
		} else {
			apikey = *breachDirectoryAPIKeyLong
		}
		fmt.Println(strings.Repeat("⎯", 85))
		strings.Repeat("⎯", 85)
		wg.Add(1)
		go SearchBreachDirectory(username, apikey, &wg)
		wg.Wait()
	}

	wg.Add(1)
	fmt.Println(strings.Repeat("⎯", 85))
	WriteToFile(username, strings.Repeat("⎯", 85))
	go SearchProxyNova(username, &wg)
	wg.Wait()

	domains := BuildDomains(username)
	fmt.Println(strings.Repeat("⎯", 85))
	strings.Repeat("⎯", 85)
	wg.Add(1)
	go SearchDomains(username, domains, &wg)
	wg.Wait()

	elapsed := time.Since(start)
	fmt.Println(strings.Repeat("⎯", 85))
	WriteToFile(username, strings.Repeat("⎯", 85))
	fmt.Println(":: Number of profiles found              : ", count.Load())
	fmt.Println(":: Total time taken                      : ", elapsed)
	WriteToFile(username, ":: Number of profiles found              : "+strconv.Itoa(int(count.Load())))
	WriteToFile(username, ":: Total time taken                      : "+elapsed.String())
}
