// GitHub Scraper module

package main

import (
	"fmt"
	"unsafe"
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
	Followers        []GitHubFollowers    `json:"followers,omitempty"`
	Following        []GitHubFollowing     `json:"following,omitempty"`
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



func FindMutualFollowers(followers []GitHubFollowers, following []GitHubFollowing) []string {

	var mutualFollowers []string

	if unsafe.Sizeof(GitHubFollowers{}) > unsafe.Sizeof(GitHubFollowing{}) {
		hashmap := make(map[string]GitHubFollowing)

		for _, followed := range following {
			hashmap[followed.ID] = followed
		}

		for _, follower := range followers {
			if follower, exists := hashmap[follower.ID]; exists {
				mutualFollowers = append(mutualFollowers, follower.Login)
			}
		}

	} else {
		hashmap := make(map[string]GitHubFollowers)

		for _, follower := range followers {
			hashmap[follower.ID] = follower
		}

		for _, followed := range following {
			if followed, exists := hashmap[followed.ID]; exists {
				mutualFollowers = append(mutualFollowers, followed.Login)
			}
		}

	}

	return mutualFollowers
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