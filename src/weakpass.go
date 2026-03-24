// Weakpass Module

package main

import (
	"io"
	"fmt"
	"net/http"
	"encoding/json"
)

type WeakpassResponse struct {
	Type string `json:"type"`
	Hash string `json:"hash"`
	Pass string `json:"pass"`
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
	err = json.Unmarshal(jsonData, &weakpass)
	if err != nil {
		fmt.Printf("Error unmarshalling JSON: %v\n", err)
		return ""
	}
	return weakpass.Pass
}