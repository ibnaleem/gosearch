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
	NodeID           string     `json:"node_id,omitempty"`
	GravatarID	     string 	 `json:"gravatar_id,omitempty"`
	AvatarURL        string     `json:"avatar_url,omitempty"`
	TwitterUsername  string		`json:"twitter_username,omitempty"`
	Name 		     string 	 `json:"name,omitempty"`
	Company 	     string 	 `json:"company,omitempty"`
	Blog             string     `json:"blog,omitempty"`
	Location         string     `json:"location,omitempty"`
	Email            string     `json:"email,omitempty"`
	Bio              string     `json:"bio,omitempty"`
	PublicRepos      string     `json:"public_repo,omitempty"`
	PublicGists      string     `json:"public_gists,omitempty"`
	Followers        string     `json:"followers,omitempty"`
	Following        string     `json:"following,omitempty"`
	CreatedAt        string     `json:"created_at,omitempty"`
	UpdatedAt        string     `json:"updated_at,omitempty"`
}

type GitHubFollowers struct {
	Login 	        string 		`json:"login,omitempty"`
	ID 				string 		`json:"id,omitempty"`
}

type GitHubFollowing struct {

	Login 	        string 		`json:"login,omitempty"`
	ID 				string 		`json:"id,omitempty"`

}

var mutualFollowers = []string{}



func UnmarshalStruct[T any](url string, isArray bool) (any, error) {
    // Since GoSearch unmarshals JSON plenty, we can create a function that returns the type
	// This prevents repetitive code

	client := http.Client{}

	var zero any

	req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			log.Fatal("In function UnmarshalStruct (line 56): ", err)
			return zero, err
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
		return zero, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Errorf("failed to fetch API in UnmarshalStruct, line 81, status code: %d", resp.StatusCode)
		return zero, err
	}

	JSONData, err := io.ReadAll(resp.Body)


	if isArray {
		var successObj []T
		err = json.Unmarshal(JSONData, &successObj)
		if err != nil {
			return zero, fmt.Errorf("error unmarshalling JSON (array): %w", err)
		}
		return successObj, nil
	} else {
		var successObj T
		err = json.Unmarshal(JSONData, &successObj)
		if err != nil {
			return zero, fmt.Errorf("error unmarshalling JSON (singular): %w", err)
		}
		return successObj, nil
	}

}


func DisplayGitHubInfo(githubUser GitHubUser, username string) {

	Greenf("[+] GitHub username found: %s", username)
	Greenf("[+] ↳ Created at: %s", githubUser.CreatedAt)
	Greenf("[+] ↳ Updated at: %s", githubUser.UpdatedAt)

	if githubUser.Name != "" {
		Greenf("[+] ↳ Name: %s", githubUser.Name)
	}

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

	if githubUser.GravatarID != "" {
		Greenf("[+] ↳ Gravatar ID: %s", githubUser.GravatarID)
	}

	if githubUser.TwitterUsername != "" {
		Greenf("[+] ↳ Twitter username: %s", githubUser.TwitterUsername)
	}

	if githubUser.AvatarURL != "" {
		Greenf("[+] ↳ Avatar URL: %s", githubUser.AvatarURL)
	}

	Greenf("[+] ↳ Number of public repositories: %s", githubUser.PublicRepos)
	Greenf("[+] ↳ Number of public gists: %s", githubUser.PublicGists)

	Greenf("[+] ↳ Number of followers: %s", githubUser.Followers)
	Greenf("[+] ↳ Number of people they follow: %s", githubUser.Following)

	Greenf("[+] ↳ Node ID: %s", githubUser.NodeID)
}