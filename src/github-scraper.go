// GitHub Scraper module

package main

import (
	"fmt"
	"log"
	"io"
	"net/http"
	"encoding/json"
)

type GitHubUser struct {
	NodeID        string     `json:"node_id,omitempty"`
	GravatarID	  string 	 `json:"gravatar_id,omitempty"`
	Name 		  string 	 `json:"name,omitempty"`
	Company 	  string 	 `json:"company,omitempty"`
	Blog          string     `json:"blog,omitempty"`
	Location      string     `json:"location,omitempty"`
	Email         string     `json:"email,omitempty"`
	Bio           string     `json:"bio,omitempty"`
	PublicRepos   string     `json:"public_repo,omitempty"`
	PublicGists   string     `json:"public_gists,omitempty"`
	Followers     string     `json:"followers,omitempty"`
	Following     string     `json:"following,omitempty"`
	CreatedAt     string     `json:"created_at,omitempty"`
	UpdatedAt     string     `json:"updated_at,omitempty"`
}

var mutualFollowers = []string{}


func UnmarshalGitHubProfile(username string) {
	client := http.Client{}

	url := fmt.Sprintf("https://api.github.com/users/%s", username)

	req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			log.Fatal("In function ScrapeGitHubProfile (line 36): ", err)
			return
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
		log.Fatal(err)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Errorf("failed to fetch GitHub profile in ScrapeGitHubProfile, line 54, status code: %d", resp.StatusCode)
		return
	}

	githubJSONData, err := io.ReadAll(resp.Body)


	var githubUser GitHubUser

	err = json.Unmarshal(githubJSONData, &githubUser)

	if err != nil {
		fmt.Errorf("error unmarshalling JSON in utils.go line 154: %w", err)
		return
	}

	DisplayGitHubInfo(githubUser, username)
}

func DisplayGitHubInfo(githubUser GitHubUser, username string) {

	Greenf("[+] GitHub username found: %s", username)
	Greenf("[+] ↳ Created at: %s", githubUser.CreatedAt)
	Greenf("[+] ↳ Updated at: %s", githubUser.UpdatedAt)

	if githubUser.Email != "" {
		Greenf("[+] ↳ Email: %s", githubUser.Email)
	}

	if githubUser.Location != "" {
		Greenf("[+] ↳ Current location: %s", githubUser.Location)
	}

	if githubUser.Bio != "" {
		Greenf("[+] ↳ Bio: %s", githubUser.Bio)
	}

	if githubUser.Company != "" {
		Greenf("[+] ↳ Current company: %s", githubUser.Company)
	}

	if githubUser.Blog != "" {
		Greenf("[+] ↳ Blog/personal website: %s", githubUser.Blog)
	}

	Greenf("[+] ↳ Number of public repositories: %s", githubUser.PublicRepos)
	Greenf("[+] ↳ Number of public gists: %s", githubUser.PublicGists)

	Greenf("[+] ↳ Number of followers: %s", githubUser.Followers)
	Greenf("[+] ↳ Number of people they follow: %s", githubUser.Following)

	Greenf("[+] ↳ Node ID: %s", githubUser.NodeID)
}