// GitHub Scraper module

package main

import (
	"fmt"
	"net/http"
	"log"
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
	PublicRepos      int     `json:"public_repo,omitempty"`
	PublicGists      int     `json:"public_gists,omitempty"`
	Followers        int    `json:"followers,omitempty"`
	Following        int    `json:"following,omitempty"`
	CreatedAt        string     `json:"created_at,omitempty"`
	UpdatedAt        string     `json:"updated_at,omitempty"`
}

type GitHubFollowers struct {
	Login 	        string 		`json:"login,omitempty"`
}

type GitHubFollowing struct {

	Login 	        string 		`json:"login,omitempty"`

}



func FindMutualFollowers(followers []GitHubFollowers, username string) ([]string, error) {

	var mutualFollowers []string

	client := http.Client{}

	for _, follower := range followers {

		following_url := fmt.Sprintf("https://api.github.com/users/%s/following/%s", username, follower.Login)

		req, err := http.NewRequest(http.MethodGet, following_url, nil)

		req.Header.Set("User-Agent", DefaultUserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Cache-Control", "max-age=0")

		if err != nil {
			log.Fatal("In function FindMutualFollowers (line 52): ", err)
			return mutualFollowers, err
		}

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
	if len(mutualFollowers) > 10 {
		top10 := mutualFollowers[:10]

		fmt.Println("[+] Top 10 Mutual Followers:")

		for i := range(top10) {
			fmt.Printf("[+] ↳ %s", i)
		}
	} else {
		fmt.Println("[+] Mutual Followers:")

		for i := range(mutualFollowers) {
			fmt.Printf("[+] ↳ %s", i)
		}
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