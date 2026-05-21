package github

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/theme"
)

type GitHubFollowers struct {
	Login string `json:"login"`
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
		top10 := mutualFollowers[:10]
		theme.Green("[+] Top 10 Mutual Followers:").Println()
		for i := range top10 {
			theme.Greenf("[+] ↳ %d", i).Println()
		}
	}

	if len(mutualFollowers) > 0 {
		theme.Green("[+] Mutual Followers:").Println()
		for i := range mutualFollowers {
			theme.Greenf("[+] ↳ %d", i).Println()
		}
	}
}
