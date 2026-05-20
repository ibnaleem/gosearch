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

type GitHubUser struct {
	NodeID          string `json:"node_id"`
	GravatarID      string `json:"gravatar_id"`
	AvatarURL       string `json:"avatar_url"`
	TwitterUsername string `json:"twitter_username"`
	Name            string `json:"name"`
	Company         string `json:"company"`
	Blog            string `json:"blog"`
	Location        string `json:"location"`
	Email           string `json:"email"`
	Bio             string `json:"bio"`
	PublicRepos     int    `json:"public_repos"`
	PublicGists     int    `json:"public_gists"`
	Followers       int    `json:"followers"`
	Following       int    `json:"following"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type GitHubFollowers struct {
	Login string `json:"login"`
}

func UnmarshalGitHubUser(username string) (GitHubUser, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s", username)
	resp, err := http.Get(url)
	if err != nil {
		return GitHubUser{}, fmt.Errorf("error fetching user %s: %w", username, err)
	}
	defer resp.Body.Close()

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return GitHubUser{}, fmt.Errorf("error reading response body for user %s: %w", username, err)
	}

	var githubUser GitHubUser
	err = json.Unmarshal(jsonData, &githubUser)
	if err != nil {
		return GitHubUser{}, fmt.Errorf("error unmarshalling response for user %s: %w", username, err)
	}

	return githubUser, nil
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
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
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
		top10 := mutualFollowers[:10]
		theme.Green("[+] Top 10 Mutual Followers:").Println()
		for i := range top10 {
			theme.Greenf("[+] ↳ %s", i).Println()
		}
	}

	if len(mutualFollowers) > 0 {
		theme.Green("[+] Mutual Followers:").Println()
		for i := range mutualFollowers {
			theme.Greenf("[+] ↳ %s", i).Println()
		}
	}
}

func DisplayGitHubInfo(githubUser GitHubUser, username string) {
	theme.Greenf("[+] GitHub username found: %s", username).Println()
	theme.Greenf("[+] ↳ Created at: %s", githubUser.CreatedAt).Println()
	theme.Greenf("[+] ↳ Updated at: %s", githubUser.UpdatedAt).Println()

	if githubUser.Name != "" {
		theme.Greenf("[+] ↳ Name: %s", githubUser.Name).Println()
	}
	if githubUser.Email != "" {
		theme.Greenf("[+] ↳ Email: %s", githubUser.Email).Println()
	}
	if githubUser.Location != "" {
		theme.Greenf("[+] ↳ Current location: %s", githubUser.Location).Println()
	}
	if githubUser.Bio != "" {
		theme.Greenf("[+] ↳ Bio: %s", githubUser.Bio).Println()
	}
	if githubUser.Company != "" {
		theme.Greenf("[+] ↳ Current company: %s", githubUser.Company).Println()
	}
	if githubUser.Blog != "" {
		theme.Greenf("[+] ↳ Blog/personal website: %s", githubUser.Blog).Println()
	}
	if githubUser.GravatarID != "" {
		theme.Greenf("[+] ↳ Gravatar ID: %s", githubUser.GravatarID).Println()
	}
	if githubUser.TwitterUsername != "" {
		theme.Greenf("[+] ↳ Twitter username: %s", githubUser.TwitterUsername).Println()
	}
	if githubUser.AvatarURL != "" {
		theme.Greenf("[+] ↳ Avatar URL: %s", githubUser.AvatarURL).Println()
	}

	theme.Greenf("[+] ↳ Number of public repositories: %d", githubUser.PublicRepos).Println()
	theme.Greenf("[+] ↳ Number of public gists: %d", githubUser.PublicGists).Println()
	theme.Greenf("[+] ↳ Number of followers: %d", githubUser.Followers).Println()
	theme.Greenf("[+] ↳ Number of people they follow: %d", githubUser.Following).Println()
	theme.Greenf("[+] ↳ Node ID: %s", githubUser.NodeID).Println()

	fmt.Println()
}
