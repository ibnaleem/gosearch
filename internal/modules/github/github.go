package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/theme"
	"github.com/ibnaleem/gosearch/internal/utils"
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


func setAuthHeader(req *http.Request) {
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func UnmarshalGitHubUser(username string) (GitHubUser, error) {
	client := &http.Client{}
	url := fmt.Sprintf("https://api.github.com/users/%s", username)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return GitHubUser{}, fmt.Errorf("error creating request for user %s: %w", username, err)
	}
	req.Header.Set("User-Agent", config.DefaultUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	setAuthHeader(req)

	resp, err := client.Do(req)
	if err != nil {
		return GitHubUser{}, fmt.Errorf("error fetching user %s: %w", username, err)
	}
	defer resp.Body.Close()

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return GitHubUser{}, fmt.Errorf("error reading response body for user %s: %w", username, err)
	}

	var githubUser GitHubUser
	if err = json.Unmarshal(jsonData, &githubUser); err != nil {
		return GitHubUser{}, fmt.Errorf("error unmarshalling response for user %s: %w", username, err)
	}

	return githubUser, nil
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
		utils.WriteEmailToFile(username, githubUser.Email)
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
