package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/models"
)

var mu sync.Mutex

// path separators plus characters Windows rejects in file names
var fileNameReplacer = strings.NewReplacer(
	"/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_",
)

// safeFileName stops a username like "../x" escaping the output directory
func safeFileName(username string) string {
	return fileNameReplacer.Replace(username)
}

func DeleteOldFile(username string) {
	os.Remove(fmt.Sprintf("%s.txt", safeFileName(username)))
}

func WriteToFile(username string, content string) {
	mu.Lock()
	defer mu.Unlock()

	if _, err := os.Stat(config.OutputDir); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(config.OutputDir, os.ModePerm); err != nil {
				log.Fatal("Error creating output directory:", err)
			}
		} else {
			log.Fatal("Error checking output directory:", err)
		}
	}

	filePath := filepath.Join(config.OutputDir, fmt.Sprintf("%s_%s.txt", safeFileName(username), time.Now().Format("2006-01-02")))

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if _, err = f.WriteString(content); err != nil {
		log.Fatal(err)
	}
}

func WriteEmailToFile(username string, email string) {
	if _, err := os.Stat(config.OutputDir); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(config.OutputDir, os.ModePerm); err != nil {
				log.Fatal("Error creating output directory:", err)
			}
		} else {
			log.Fatal("Error checking output directory:", err)
		}
	}

	filePath := filepath.Join(config.OutputDir, fmt.Sprintf("%s_emails.txt", safeFileName(username)))

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModePerm)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	if _, err = f.WriteString(email); err != nil {
		log.Fatal(err)
	}
}

// a username used as a subdomain must be a single DNS label (RFC 1123)
var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// placeholderInHost reports whether {} sits in the hostname, e.g. https://{}.tumblr.com.
// It intentionally treats a placeholder in a path/query/fragment as not being in the host.
func placeholderInHost(baseURL string) bool {
	placeholder := strings.Index(baseURL, "{}")
	if placeholder < 0 {
		return false
	}

	start := 0
	if scheme := strings.Index(baseURL, "://"); scheme >= 0 {
		start = scheme + len("://")
	}

	end := strings.IndexAny(baseURL[start:], "/?#")
	if end < 0 {
		end = len(baseURL) - start
	}
	return placeholder < start+end
}

// CanBuildURL reports whether username can be safely put into baseURL.
// Path and query placeholders can always be escaped; hostnames cannot.
func CanBuildURL(baseURL, username string) bool {
	return !placeholderInHost(baseURL) || dnsLabel.MatchString(username)
}

// BuildURL substitutes username into each {} placeholder, escaping it for the
// part of the URL it lands in. Hostname placeholders are left raw, so callers
// must check CanBuildURL first.
func BuildURL(baseURL, username string) string {
	if !strings.Contains(baseURL, "{}") {
		return baseURL
	}

	var b strings.Builder
	start := 0
	for {
		idx := strings.Index(baseURL[start:], "{}")
		if idx < 0 {
			b.WriteString(baseURL[start:])
			return b.String()
		}
		idx += start

		b.WriteString(baseURL[start:idx])
		replacement := username
		if !placeholderInHost(baseURL[:idx+2]) {
			if strings.ContainsAny(baseURL[:idx], "?#") {
				replacement = url.QueryEscape(username)
			} else {
				replacement = url.PathEscape(username)
			}
		}
		b.WriteString(replacement)
		start = idx + len("{}")
	}
}

func BuildDomains(username string) []string {
	if !dnsLabel.MatchString(username) {
		return nil
	}

	tlds := []string{
		".com", ".net", ".org", ".biz", ".info", ".name", ".pro", ".cat",
		".co", ".me", ".io", ".tech", ".dev", ".app", ".shop", ".fail",
		".xyz", ".blog", ".portfolio", ".store", ".online", ".about",
		".space", ".lol", ".fun", ".social",
	}

	var domains []string
	for _, tld := range tlds {
		domains = append(domains, username+tld)
	}
	return domains
}

func UnmarshalJSON() (models.Data, error) {

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	url := "https://raw.githubusercontent.com/ibnaleem/gosearch/refs/heads/main/data.json"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return models.Data{}, fmt.Errorf("error creating HTTP request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return models.Data{}, fmt.Errorf("error downloading data.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Failed to download data.json, using local copy instead...")
		localJsonData, err := os.ReadFile("data.json")
		if err != nil {
			return models.Data{}, fmt.Errorf("error reading local data.json: %w", err)
		}

		var data models.Data
		err = json.Unmarshal(localJsonData, &data)
		if err != nil {
			return models.Data{}, fmt.Errorf("error unmarshalling local JSON: %w", err)
		}
		return data, nil
	}

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.Data{}, fmt.Errorf("error reading downloaded content: %w", err)
	}

	var data models.Data
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		return models.Data{}, fmt.Errorf("error unmarshalling JSON: %w", err)
	}

	return data, nil
}
