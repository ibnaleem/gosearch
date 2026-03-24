// GitHub Scraper module

package main

import (
	"fmt"
	"net/http"
	"log"
)

type GitHubUser struct {
	NodeID           string     `json:"node_id"`
	GravatarID	     string 	 `json:"gravatar_id"`
	AvatarURL        string     `json:"avatar_url"`
	TwitterUsername  string		`json:"twitter_username"`
	Name 		     string 	 `json:"name"`
	Company 	     string 	 `json:"company"`
	Blog             string     `json:"blog"`
	Location         string     `json:"location"`
	Email            string     `json:"email"`
	Bio              string     `json:"bio"`
	PublicRepos      int     `json:"public_repos"`
	PublicGists      int     `json:"public_gists"`
	Followers        int    `json:"followers"`
	Following        int    `json:"following"`
	CreatedAt        string     `json:"created_at"`
	UpdatedAt        string     `json:"updated_at"`
}

type GitHubFollowers struct {
	Login 	        string 		`json:"login"`
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
	
	fmt.Println()
	
	if len(mutualFollowers) > 10 {
		top10 := mutualFollowers[:10]


		Green("[+] Top 10 Mutual Followers:").Println()

		for i := range(top10) {
			Greenf("[+] ↳ %s", i).Println()
		}
	} 
	
	if len(mutualFollowers) > 0 {
		Green("[+] Mutual Followers:").Println()

		for i := range(mutualFollowers) {
			Greenf("[+] ↳ %s", i).Println()
		}
	} else {
		return
	}
}

func DisplayGitHubInfo(githubUser GitHubUser, username string) {

	fmt.Println()

	Greenf("[+] GitHub username found: %s", username).Println()
	Greenf("[+] ↳ Created at: %s", githubUser.CreatedAt).Println()
	Greenf("[+] ↳ Updated at: %s", githubUser.UpdatedAt).Println()

	if githubUser.Name != "" {
		Greenf("[+] ↳ Name: %s", githubUser.Name).Println()
	}

	if githubUser.Email != "" {
		Greenf("[+] ↳ Email: %s", githubUser.Email).Println()
	}

	if githubUser.Location != "" {
		Greenf("[+] ↳ Current location: %s", githubUser.Location).Println()
	}

	if githubUser.Bio != "" {
		Greenf("[+] ↳ Bio: %s", githubUser.Bio).Println()
	}

	if githubUser.Company != "" {
		Greenf("[+] ↳ Current company: %s", githubUser.Company).Println()
	}

	if githubUser.Blog != "" {
		Greenf("[+] ↳ Blog/personal website: %s", githubUser.Blog).Println()
	}

	if githubUser.GravatarID != "" {
		Greenf("[+] ↳ Gravatar ID: %s", githubUser.GravatarID).Println()
	}

	if githubUser.TwitterUsername != "" {
		Greenf("[+] ↳ Twitter username: %s", githubUser.TwitterUsername).Println()
	}

	if githubUser.AvatarURL != "" {
		Greenf("[+] ↳ Avatar URL: %s", githubUser.AvatarURL).Println()
	}

	Greenf("[+] ↳ Number of public repositories: %d", githubUser.PublicRepos).Println()
	Greenf("[+] ↳ Number of public gists: %d", githubUser.PublicGists).Println()

	Greenf("[+] ↳ Number of followers: %d", githubUser.Followers).Println()
	Greenf("[+] ↳ Number of people they follow: %d", githubUser.Following).Println()

	Greenf("[+] ↳ Node ID: %s", githubUser.NodeID).Println()
}