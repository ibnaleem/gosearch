package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ibnaleem/gosearch/internal/config"
)

// ExtractEmailsFromCommits returns a deduplicated map of email -> author name
// from PushEvents, filtering out GitHub's noreply privacy addresses.
func ExtractEmailsFromCommits(events []GitHubEvent) map[string]string {
	emails := make(map[string]string)

	for _, event := range events {
		if event.Type != "PushEvent" {
			continue
		}
		for _, commit := range event.Payload.Commits {
			if commit.Author.Email == "" || strings.Contains(commit.Author.Email, "noreply.github.com") {
				continue
			}
			emails[commit.Author.Email] = commit.Author.Name
		}
	}

	return emails
}

func FetchPublicEvents(username string) ([]GitHubEvent, error) {
	var allEvents []GitHubEvent
	client := &http.Client{}

	for page := 1; page <= 10; page++ {
		url := fmt.Sprintf("https://api.github.com/users/%s/events/public?page=%d", username, page)

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return allEvents, fmt.Errorf("error creating request: %w", err)
		}
		req.Header.Set("User-Agent", config.DefaultUserAgent)
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := client.Do(req)
		if err != nil {
			return allEvents, fmt.Errorf("error fetching events: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return allEvents, fmt.Errorf("error reading response: %w", err)
		}

		var events []GitHubEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return allEvents, fmt.Errorf("error parsing events: %w", err)
		}

		if len(events) == 0 {
			break
		}

		allEvents = append(allEvents, events...)
	}

	return allEvents, nil
}

type GitHubEvent struct {
	Type    string            `json:"type"`
	Payload GitHubPushPayload `json:"payload"`
}

type GitHubPushPayload struct {
	Commits []GitHubCommit `json:"commits"`
}

type GitHubCommit struct {
	Author  GitHubCommitAuthor `json:"author"`
	Message string             `json:"message"`
}

type GitHubCommitAuthor struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}
