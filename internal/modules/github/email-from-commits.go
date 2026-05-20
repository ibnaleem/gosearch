package github

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
