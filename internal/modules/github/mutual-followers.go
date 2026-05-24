package github

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/theme"
)

type GitHubFollowers struct {
	Login string `json:"login"`
}

func FetchFollowers(username string) ([]GitHubFollowers, error) {
	client := &http.Client{}
	url := fmt.Sprintf("%s/users/%s/followers?per_page=100", githubAPIBase, username)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("User-Agent", config.DefaultUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	setAuthHeader(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching followers: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d — unauthenticated requests are limited to 60 req/hour; set GITHUB_TOKEN for 5,000 req/hour", resp.StatusCode)
	}

	var followers []GitHubFollowers
	if err := json.Unmarshal(body, &followers); err != nil {
		return nil, fmt.Errorf("error parsing followers: %w", err)
	}

	return followers, nil
}

func FindMutualFollowers(followers []GitHubFollowers, username string) ([]string, error) {
	var mutualFollowers []string

	client := http.Client{}

	for _, follower := range followers {
		followingURL := fmt.Sprintf("https://api.github.com/users/%s/following/%s", username, follower.Login)

		req, err := http.NewRequest(http.MethodGet, followingURL, nil)
		if err != nil {
			log.Fatal("In function FindMutualFollowers: ", err)
			return mutualFollowers, err
		}

		req.Header.Set("User-Agent", config.DefaultUserAgent)
		req.Header.Set("Accept", "application/vnd.github+json")
		setAuthHeader(req)

		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
			return mutualFollowers, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 204 {
			mutualFollowers = append(mutualFollowers, follower.Login)
		}
	}

	return mutualFollowers, nil
}

func DisplayMutualFollowers(mutualFollowers []string) {
	fmt.Println()

	if len(mutualFollowers) > 10 {
		theme.Green("[+] Top 10 Mutual Followers:").Println()
		for _, login := range mutualFollowers[:10] {
			theme.Greenf("[+] ↳ %s", login).Println()
		}
	}

	if len(mutualFollowers) > 0 {
		theme.Green("[+] Mutual Followers:").Println()
		for _, login := range mutualFollowers {
			theme.Greenf("[+] ↳ %s", login).Println()
		}
	}
}
