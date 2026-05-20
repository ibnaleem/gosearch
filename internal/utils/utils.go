package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/models"
)

var mu sync.Mutex

func DeleteOldFile(username string) {
	os.Remove(fmt.Sprintf("%s.txt", username))
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

	filePath := filepath.Join(config.OutputDir, fmt.Sprintf("%s_%s.txt", username, time.Now().Format("2006-01-02")))

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
	err := os.Remove("data.json")
	if err != nil && !os.IsNotExist(err) {
		return models.Data{}, fmt.Errorf("error deleting old data.json: %w", err)
	}

	url := "https://raw.githubusercontent.com/ibnaleem/gosearch/refs/heads/main/data.json"
	resp, err := http.Get(url)
	if err != nil {
		return models.Data{}, fmt.Errorf("error downloading data.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return models.Data{}, fmt.Errorf("failed to download data.json, status code: %d", resp.StatusCode)
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
