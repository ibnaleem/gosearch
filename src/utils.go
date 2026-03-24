// Utility Module

package main

import (
	"io"
	"os"
	"fmt"
	"log"
	"time"
	"strings"
	"net/http"
	"encoding/json"
	"compress/gzip"
	"path/filepath"

	"github.com/bytedance/sonic"
)

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
		return t.Format("Jan 2, 2006") // e.g., "May 15, 2025"
	}
}

func DeleteOldFile(username string) {
	filename := fmt.Sprintf("%s.txt", username)
	os.Remove(filename)
}

func WriteToFile(username string, content string) {
	mu.Lock()
	defer mu.Unlock()

	if _, err := os.Stat(OutputDir); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(OutputDir, os.ModePerm); err != nil {
				log.Fatal("Error creating output directory:", err)
			}
		} else {
			log.Fatal("Error checking output directory:", err)
		}
	}

	filePath := filepath.Join(OutputDir, fmt.Sprintf("%s_%s.txt", username, time.Now().Format("2006-01-02")))

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
		return Data{}, fmt.Errorf("error unmarshalling JSON in utils.go line 154: %w", err)
	}

	return data, nil
}


func UnmarshalGitHubUser(username string) (GitHubUser, error) {

	url := fmt.Sprintf("https://api.github.com/users/%s", username)
	resp, err := http.Get(url)
	if err != nil {
		return GitHubUser{}, fmt.Errorf("utils.go (167-168):\nurl := fmt.Sprintf('https://api.github.com/users/\%s', username)\nresp, err := http.Get(url)\n\nerror fetching user %s with constructed url %s: %w", username, url, err)
	}

	defer resp.Body.Close()

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return GitHubUser{}, fmt.Errorf("utils.go (175):\njsonData, err := io.ReadAll(resp.Body)\n\nerror reading response body for user %s with constructed url %s with body length of %d: %w", username, url, len(resp.Body), err)
	}

	var githubUser GitHubUser
	err = sonic.Unmarshal(jsonData, &githubUser)
	if err != nil {
		return GitHubUser{}, fmt.Errorf("utils.go (180-181):\nvar githubUser GitHubUser\nerr = sonic.Unmarshal(jsonData, &githubUser)\n\nerror unmarshing response body using sonic for user %s with constructed url %s: %w", username, url, err) 
	}

	return githubUser, nil
}



func UnmarshalStruct[T any](url string) (T, error) {
    // Since GoSearch unmarshals JSON plenty, we can create a function that returns the type
	// This prevents repetitive code

	client := http.Client{}

	var zero T

	req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			log.Fatal("In function UnmarshalStruct (line 56): ", err)
			return zero, err
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return zero, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Errorf("failed to fetch API in UnmarshalStruct, line 81, status code: %d", resp.StatusCode)
		return zero, err
	}

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return zero, err
		}
		defer reader.Close()
	default:
		reader = resp.Body
	}

	JSONData, err := io.ReadAll(reader)
	fmt.Println(string(JSONData))


	var result T
	err = json.Unmarshal(JSONData, &result)
	if err != nil {
		return zero, fmt.Errorf("error unmarshalling JSON: %w", err)
	}

	return result, nil

}