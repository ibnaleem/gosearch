package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/theme"
	"github.com/ibnaleem/gosearch/internal/utils"
)

func countPushEvents(events []GitHubEvent) int {
	total := 0
	for _, event := range events {
		if event.Type == "PushEvent" && event.Payload.Head != "" {
			total++
		}
	}
	return total
}

func DisplayEmailsFromCommits(username string) {
	theme.Yellow("[*] Extracting emails from public commits for ", username, "...").Println()

	events, err := FetchPublicEvents(username)
	if err != nil {
		theme.Redf("[-] Error fetching public events: %v", err).Println()
		return
	}

	if len(events) == 0 {
		theme.Yellow("[!] No public events found — recent activity may be in private repositories").Println()
		utils.WriteToFile(username, "[!] No public events found\n")
		return
	}

	emails := ExtractEmailsFromCommits(events)

	if len(emails) == 0 {
		pushEvents := countPushEvents(events)
		if pushEvents > 0 {
			theme.Yellowf("[!] %d push event(s) found but no public emails discovered (email privacy may be enabled)", pushEvents).Println()
			utils.WriteToFile(username, fmt.Sprintf("[!] %d push event(s) found but no public emails discovered\n", pushEvents))
		} else {
			theme.Yellow("[!] No push events in public activity — commits may be to private repositories").Println()
			utils.WriteToFile(username, "[!] No push events in public activity\n")
		}
		return
	}

	theme.Greenf("[+] Found %d unique email(s) from commits:", len(emails)).Println()
	utils.WriteToFile(username, fmt.Sprintf("[+] Found %d unique email(s) from commits:\n", len(emails)))

	for email, name := range emails {
		theme.Greenf("[+] ↳ %s (%s)", email, name).Println()
		utils.WriteToFile(username, fmt.Sprintf("[+] ↳ %s (%s)\n", email, name))
	}
}

// ExtractEmailsFromCommits returns a deduplicated map of email -> author name.
// For each PushEvent it fetches the head commit via the commits API, since the
// public events API omits the commits array from PushEvent payloads.
func ExtractEmailsFromCommits(events []GitHubEvent) map[string]string {
	emails := make(map[string]string)

	for _, event := range events {
		if event.Type != "PushEvent" || event.Repo.Name == "" || event.Payload.Head == "" {
			continue
		}
		author, err := FetchCommit(event.Repo.Name, event.Payload.Head)
		if err != nil {
			continue
		}
		if author.Email == "" || strings.Contains(author.Email, "noreply.github.com") {
			continue
		}
		emails[author.Email] = author.Name
	}

	return emails
}

var githubAPIBase = "https://api.github.com"

func FetchCommit(repo, sha string) (GitHubCommitAuthor, error) {
	client := &http.Client{}
	url := fmt.Sprintf("%s/repos/%s/commits/%s", githubAPIBase, repo, sha)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return GitHubCommitAuthor{}, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("User-Agent", config.DefaultUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return GitHubCommitAuthor{}, fmt.Errorf("error fetching commit: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return GitHubCommitAuthor{}, fmt.Errorf("error reading response: %w", err)
	}

	var commitResp GitHubCommitResponse
	if err := json.Unmarshal(body, &commitResp); err != nil {
		return GitHubCommitAuthor{}, fmt.Errorf("error parsing commit: %w", err)
	}

	return commitResp.Commit.Author, nil
}

func FetchPublicEvents(username string) ([]GitHubEvent, error) {
	client := &http.Client{}

	url := fmt.Sprintf("%s/users/%s/events/public", githubAPIBase, username)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("User-Agent", config.DefaultUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching events: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	var events []GitHubEvent
	if err := json.Unmarshal(body, &events); err != nil {
		return nil, fmt.Errorf("error parsing events: %w", err)
	}

	return events, nil
}

type GitHubEvent struct {
	Type    string            `json:"type"`
	Repo    GitHubEventRepo   `json:"repo"`
	Payload GitHubPushPayload `json:"payload"`
}

type GitHubEventRepo struct {
	Name string `json:"name"`
}

type GitHubPushPayload struct {
	Head string `json:"head"`
}

type GitHubCommitResponse struct {
	Commit GitHubCommitDetail `json:"commit"`
}

type GitHubCommitDetail struct {
	Author  GitHubCommitAuthor `json:"author"`
	Message string             `json:"message"`
}

type GitHubCommitAuthor struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}
