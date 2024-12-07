package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"github.com/inancgumus/screen"
	"gopkg.in/yaml.v3"
	"crypto/tls"
	"time"
)

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

func MakeRequestWithErrorCode(website Website, url string, username string) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	client := &http.Client{
		Timeout:   60 * time.Second,
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
		fmt.Println(Green + "::", url + Reset)
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
		Timeout:   60 * time.Second,
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
	if !strings.Contains(bodyStr, website.ErrorMsg) {
		fmt.Println(Green + "::", url + Reset)
		WriteToFile(username, url + "\n")
		count++
	}
}

func Search(config Config, username string, wg *sync.WaitGroup) {
	var url string

	for _, website := range config.Websites {
		go func(website Website) {
			defer wg.Done() // Ensure the goroutine signals that it's done after completion

			if website.URLProbe != "" {
				url = BuildURL(website.URLProbe, username)
			} else {
				url = BuildURL(website.BaseURL, username)
			}

			if website.ErrorType == "status_code" {
				MakeRequestWithErrorCode(website, url, username)
			} else if website.ErrorType == "errorMsg" {
				MakeRequestWithErrorMsg(website, url, username)
			} else {
				fmt.Println(Yellow + ":: [?]", url + Reset)
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
	fmt.Println(strings.Repeat("⎯", 60))
	fmt.Println(":: Username                              : ", username)
	fmt.Println(":: Websites                              : ", len(config.Websites))
	fmt.Println(strings.Repeat("⎯", 60))
	fmt.Println(":: A yellow link indicates that I was unable to verify whether the username exists on the platform.")

	start := time.Now()

	wg.Add(len(config.Websites))
	go Search(config, username, &wg)
	wg.Wait()

	elapsed := time.Since(start)
	fmt.Println(strings.Repeat("⎯", 60))
	fmt.Println(":: Number of profiles found              : ", count)
	fmt.Println(":: Total time taken                      : ", elapsed)
	
	os.Exit(0)
}