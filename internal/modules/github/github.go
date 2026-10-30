package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/file"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/theme"
)

type gitHubClient struct {
	fileWriter *file.FileWriter
	out        io.Writer
	httpClient *http.Client
}

type gitHubUserResponse struct {
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

type gitHubSocialAccountResponse struct {
	Provider string `json:"provider"`
	URL      string `json:"url"`
}

type gitHubSSHKeyResponse struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
}

type gitHubGPGKeyResponse struct {
	Name      string           `json:"name"`
	KeyID     string           `json:"key_id"`
	Emails    []gitHubGPGEmail `json:"emails"`
	CreatedAt string           `json:"created_at"`
	ExpiresAt *string          `json:"expires_at"`
	Revoked   bool             `json:"revoked"`
}

type gitHubGPGEmail struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

type gitHubFollowersResponse struct {
	Login string `json:"login"`
}

type gitHubEventResponse struct {
	Type    string            `json:"type"`
	Repo    gitHubEventRepo   `json:"repo"`
	Payload gitHubPushPayload `json:"payload"`
}

type gitHubEventRepo struct {
	Name string `json:"name"`
}

type gitHubPushPayload struct {
	Head string `json:"head"`
}

type gitHubCommitResponse struct {
	Commit gitHubCommitDetail `json:"commit"`
}

type gitHubCommitDetail struct {
	Author  gitHubCommitAuthor `json:"author"`
	Message string             `json:"message"`
}

type gitHubCommitAuthor struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

func NewGitHubClient(out io.Writer, fileWriter *file.FileWriter) modules.Module {
	httpClient := config.NewHTTPClient()

	return &gitHubClient{
		fileWriter: fileWriter,
		out:        out,
		httpClient: httpClient,
	}
}

func (ghc *gitHubClient) Name() string {
	return "Github"
}

// headers returns what every GitHub API request sends on top of the defaults:
// the GitHub JSON media type and, when GITHUB_TOKEN is set, the token.
func (ghc *gitHubClient) headers() map[string]string {
	headers := map[string]string{"Accept": "application/vnd.github+json"}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", token)
	}

	return headers
}

func (ghc *gitHubClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	user, err := ghc.searchUser(ctx, query)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, nil
	}

	var failed []string

	// optional steps log their error and let the search carry on, so one
	// rate-limited lookup doesn't drop the profile that was already found
	optional := func(step string, err error) error {
		if err == nil {
			return nil
		}

		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		theme.Redf("[!] %s %s: %v", ghc.Name(), step, err).Fprintln(ghc.out)
		failed = append(failed, step)

		return nil
	}

	socialProfile, err := ghc.searchSocialProfile(ctx, query)
	if err := optional("social accounts", err); err != nil {
		return nil, err
	}

	sshKeys, err := ghc.searchSSHKeys(ctx, query)
	if err := optional("SSH keys", err); err != nil {
		return nil, err
	}

	gpgKeys, err := ghc.searchGPGKey(ctx, query)
	if err := optional("GPG keys", err); err != nil {
		return nil, err
	}

	mutualFollowers, err := ghc.searchMutualFollowers(ctx, query, user.Followers)
	if err := optional("mutual followers", err); err != nil {
		return nil, err
	}

	emails, err := ghc.searchEmailFromCommits(ctx, query)
	if err := optional("commit emails", err); err != nil {
		return nil, err
	}

	summary := fmt.Sprintf(
		"1 profile found, %d social account(s), %d SSH key(s), %d GPG key(s), %d mutual follower(s), %d commit email(s)",
		len(socialProfile), len(sshKeys), len(gpgKeys), len(mutualFollowers), len(emails),
	)

	if len(failed) > 0 {
		summary += "; failed: " + strings.Join(failed, ", ")
	}

	result := modules.Result{
		Module:  ghc.Name(),
		Summary: summary,
	}

	return &result, nil
}

func (ghc *gitHubClient) searchUser(ctx context.Context, query string) (*gitHubUserResponse, error) {
	theme.Cyanf("[*] Searching %s on Github...", query).Fprintln(ghc.out)
	response, err := ghc.buildUserRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if response.NodeID == "" {
		theme.Redf("[-] No Github profile found for %s", query).Fprintln(ghc.out)
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] GitHub username found: %s", query).Fprintln(ghc.out)
	fmt.Fprintf(&buffer, "[+] GitHub username found: %s\n", query)

	theme.Greenf(":: %03d :: %-16s : %s", 1, "Created at", response.CreatedAt).Fprintln(ghc.out)
	fmt.Fprintf(&buffer, ":: %03d :: %-16s : %s\n", 1, "Created at", response.CreatedAt)

	theme.Greenf("          %-16s : %s", "Updated at", response.UpdatedAt).Fprintln(ghc.out)
	fmt.Fprintf(&buffer, "          %-16s : %s\n", "Updated at", response.UpdatedAt)

	if response.Name != "" {
		theme.Greenf("          %-16s : %s", "Name", response.Name).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Name", response.Name)
	}

	if response.Email != "" {
		theme.Greenf("          %-16s : %s", "Email", response.Email).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Email", response.Email)
	}

	if response.Location != "" {
		theme.Greenf("          %-16s : %s", "Current location", response.Location).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Current location", response.Location)
	}

	if response.Bio != "" {
		theme.Greenf("          %-16s : %s", "Bio", response.Bio).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Bio", response.Bio)
	}

	if response.Company != "" {
		theme.Greenf("          %-16s : %s", "Current company", response.Company).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Current company", response.Company)
	}

	if response.Blog != "" {
		theme.Greenf("          %-16s : %s", "Blog", response.Blog).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Blog", response.Blog)
	}

	if response.GravatarID != "" {
		theme.Greenf("          %-16s : %s", "Gravatar ID", response.GravatarID).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Gravatar ID", response.GravatarID)
	}

	if response.TwitterUsername != "" {
		theme.Greenf("          %-16s : %s", "Twitter username", response.TwitterUsername).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Twitter username", response.TwitterUsername)
	}

	if response.AvatarURL != "" {
		theme.Greenf("          %-16s : %s", "Avatar URL", response.AvatarURL).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Avatar URL", response.AvatarURL)
	}

	theme.Greenf("          %-16s : %d", "Public repos", response.PublicRepos).Fprintln(ghc.out)
	theme.Greenf("          %-16s : %d", "Public gists", response.PublicGists).Fprintln(ghc.out)
	theme.Greenf("          %-16s : %d", "Followers", response.Followers).Fprintln(ghc.out)
	theme.Greenf("          %-16s : %d", "Following", response.Following).Fprintln(ghc.out)
	theme.Greenf("          %-16s : %s", "Node ID", response.NodeID).Fprintln(ghc.out)

	fmt.Fprintf(&buffer, "          %-16s : %d\n", "Public repos", response.PublicRepos)
	fmt.Fprintf(&buffer, "          %-16s : %d\n", "Public gists", response.PublicGists)
	fmt.Fprintf(&buffer, "          %-16s : %d\n", "Followers", response.Followers)
	fmt.Fprintf(&buffer, "          %-16s : %d\n", "Following", response.Following)
	fmt.Fprintf(&buffer, "          %-16s : %s\n", "Node ID", response.NodeID)

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(ghc.out)
	}

	return response, nil
}

func (ghc *gitHubClient) buildUserRequest(ctx context.Context, query string) (*gitHubUserResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s", url.PathEscape(query))

	response, err := modules.FetchJSON[gitHubUserResponse](ctx, ghc.httpClient, endpoint, ghc.headers())
	if err != nil {
		return nil, fmt.Errorf("%s(buildUserRequest): %w", ghc.Name(), err)
	}

	return response, nil
}

func (ghc *gitHubClient) searchSocialProfile(ctx context.Context, query string) ([]gitHubSocialAccountResponse, error) {
	theme.Cyanf("[*] Searching %s on Github for social accounts...", query).Fprintln(ghc.out)

	response, err := ghc.buildSocialAccountRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		theme.Redf("[-] No social accounts found").Fprintln(ghc.out)
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d social account(s):", len(response)).Fprintln(ghc.out)
	fmt.Fprintf(&buffer, "[+] Found %d social account(s):\n", len(response))

	for index, account := range response {
		theme.Greenf(":: %03d :: %-10s : %s", index+1, account.Provider, account.URL).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, ":: %03d :: %-10s : %s\n", index+1, account.Provider, account.URL)
	}

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(ghc.out)
	}

	return response, nil
}

func (ghc *gitHubClient) buildSocialAccountRequest(ctx context.Context, query string) ([]gitHubSocialAccountResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/social_accounts", url.PathEscape(query))

	response, err := modules.FetchJSON[[]gitHubSocialAccountResponse](ctx, ghc.httpClient, endpoint, ghc.headers())
	if err != nil {
		return nil, fmt.Errorf("%s(buildSocialAccountRequest): %w", ghc.Name(), err)
	}

	return *response, nil
}

func (ghc *gitHubClient) searchSSHKeys(ctx context.Context, query string) ([]gitHubSSHKeyResponse, error) {
	theme.Cyanf("[*] Searching %s on Github for SSH keys...", query).Fprintln(ghc.out)

	response, err := ghc.buildSSHKeyRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		theme.Redf("[-] No public SSH keys found for %s", query).Fprintln(ghc.out)
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d SSH key(s):", len(response)).Fprintln(ghc.out)
	fmt.Fprintf(&buffer, "[+] Found %d SSH key(s):\n", len(response))

	for index, key := range response {
		keyType := strings.SplitN(key.Key, " ", 2)[0]
		theme.Greenf(":: %03d :: %-10s : id %d", index+1, keyType, key.ID).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, ":: %03d :: %-10s : id %d\n", index+1, keyType, key.ID)
	}

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(ghc.out)
	}

	return response, nil
}

func (ghc *gitHubClient) buildSSHKeyRequest(ctx context.Context, query string) ([]gitHubSSHKeyResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/keys", url.PathEscape(query))

	response, err := modules.FetchJSON[[]gitHubSSHKeyResponse](ctx, ghc.httpClient, endpoint, ghc.headers())
	if err != nil {
		return nil, fmt.Errorf("%s(buildSSHKeyRequest): %w", ghc.Name(), err)
	}

	return *response, nil
}

func (ghc *gitHubClient) searchGPGKey(ctx context.Context, query string) ([]gitHubGPGKeyResponse, error) {
	theme.Cyanf("[*] Searching %s on Github for GPG keys...", query).Fprintln(ghc.out)

	response, err := ghc.buildGPGKeyRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		theme.Redf("[-] No public GPG keys found for %s", query).Fprintln(ghc.out)
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d GPG key(s):", len(response)).Fprintln(ghc.out)
	fmt.Fprintf(&buffer, "[+] Found %d GPG key(s):\n", len(response))

	for index, key := range response {
		info := key.KeyID
		if key.Name != "" {
			info = fmt.Sprintf("%s (%s)", key.KeyID, key.Name)
		}

		theme.Greenf(":: %03d :: %-11s : %s", index+1, "Fingerprint", info).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, ":: %03d :: %-11s : %s\n", index+1, "Fingerprint", info)

		for _, email := range key.Emails {
			verified := ""
			if email.Verified {
				verified = " (verified)"
			}

			theme.Greenf("          %-11s : %s%s", "Email", email.Email, verified).Fprintln(ghc.out)
			fmt.Fprintf(&buffer, "          %-11s : %s%s\n", "Email", email.Email, verified)
		}

		if key.Revoked {
			theme.Yellowf("          %-11s : revoked", "Status").Fprintln(ghc.out)
			fmt.Fprintf(&buffer, "          %-11s : revoked\n", "Status")
		}
	}

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(ghc.out)
	}

	return response, nil
}

func (ghc *gitHubClient) buildGPGKeyRequest(ctx context.Context, query string) ([]gitHubGPGKeyResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/gpg_keys", url.PathEscape(query))

	response, err := modules.FetchJSON[[]gitHubGPGKeyResponse](ctx, ghc.httpClient, endpoint, ghc.headers())
	if err != nil {
		return nil, fmt.Errorf("%s(buildGPGKeyRequest): %w", ghc.Name(), err)
	}

	return *response, nil
}

func (ghc *gitHubClient) searchMutualFollowers(ctx context.Context, query string, totalFollowers int) ([]string, error) {
	theme.Cyanf("[*] Searching %s on Github for mutual followers...", query).Fprintln(ghc.out)

	followers, err := ghc.buildFollowersRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(followers) == 0 {
		theme.Redf("[-] No followers found for %s", query).Fprintln(ghc.out)
		return nil, nil
	}

	// a failed check is returned to Search, which reports it; only an empty
	// list from a check that completed means there are no mutual followers
	// only the first page of followers is checked, since each one costs a
	// request against GitHub's rate limit; say so when that isn't all of them
	scope := ""
	if totalFollowers > len(followers) {
		scope = fmt.Sprintf(" among the first %d of %d followers", len(followers), totalFollowers)
	}

	mutualFollowers, checkErr := ghc.buildMutualFollowersRequest(ctx, query, followers)
	if len(mutualFollowers) == 0 {
		if checkErr != nil {
			return nil, checkErr
		}

		theme.Redf("[-] No mutual followers found for %s%s", query, scope).Fprintln(ghc.out)
		return nil, nil
	}

	var buffer strings.Builder

	incomplete := ""
	if checkErr != nil {
		incomplete = " (incomplete, check stopped early)"
	}

	theme.Greenf("[+] Found %d mutual follower(s)%s%s:", len(mutualFollowers), scope, incomplete).Fprintln(ghc.out)
	fmt.Fprintf(&buffer, "[+] Found %d mutual follower(s)%s%s:\n", len(mutualFollowers), scope, incomplete)

	for index, follower := range mutualFollowers {
		theme.Greenf(":: %03d :: %s", index+1, follower).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, ":: %03d :: %s\n", index+1, follower)
	}

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(ghc.out)
	}

	return mutualFollowers, checkErr
}

func (ghc *gitHubClient) buildFollowersRequest(ctx context.Context, query string) ([]gitHubFollowersResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/followers?per_page=100", url.PathEscape(query))

	response, err := modules.FetchJSON[[]gitHubFollowersResponse](ctx, ghc.httpClient, endpoint, ghc.headers())
	if err != nil {
		return nil, fmt.Errorf("%s(buildFollowersRequest): %w", ghc.Name(), err)
	}

	return *response, nil
}

func (ghc *gitHubClient) buildMutualFollowersRequest(ctx context.Context, query string, param []gitHubFollowersResponse) ([]string, error) {
	var mutualFollowers []string

	for _, follower := range param {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		endpoint := fmt.Sprintf("https://api.github.com/users/%s/following/%s", url.PathEscape(query), url.PathEscape(follower.Login))

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("%s(buildMutualFollowersRequest): create request: %w", ghc.Name(), err)
		}

		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		}

		request.Header.Set("User-Agent", config.DefaultUserAgent)
		request.Header.Set("Accept", "application/vnd.github+json")

		response, err := ghc.httpClient.Do(request)
		if err != nil {
			return nil, fmt.Errorf("%s(buildMutualFollowersRequest): send request: %w", ghc.Name(), err)
		}

		response.Body.Close()

		switch response.StatusCode {
		case http.StatusNoContent: // HTTP 204 - following back
			mutualFollowers = append(mutualFollowers, follower.Login)

		case http.StatusNotFound: // HTTP 404 - not following back
		default:
			return mutualFollowers, fmt.Errorf("%s(buildMutualFollowersRequest): checking %s: GitHub API returned %d — unauthenticated requests are limited to 60 req/hour; set GITHUB_TOKEN for 5,000 req/hour", ghc.Name(), follower.Login, response.StatusCode)
		}
	}

	return mutualFollowers, nil
}

func (ghc *gitHubClient) searchEmailFromCommits(ctx context.Context, query string) (map[string]string, error) {
	theme.Cyanf("[*] Searching %s on Github for emails in public commits...", query).Fprintln(ghc.out)

	events, err := ghc.buildEventRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	var lookupErr error

	emails := make(map[string]string)
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if event.Type != "PushEvent" || event.Repo.Name == "" || event.Payload.Head == "" {
			continue
		}

		// a failed lookup (e.g. rate limit) would fail for the next commits too,
		// so stop here and report it instead of showing it as "no emails"
		commit, err := ghc.buildCommitRequest(ctx, event.Repo.Name, event.Payload.Head)
		if err != nil {
			lookupErr = err
			break
		}

		author := commit.Commit.Author
		if author.Email == "" || strings.Contains(author.Email, "noreply.github.com") {
			continue
		}

		emails[author.Email] = author.Name
	}

	if len(emails) == 0 {
		if lookupErr != nil {
			return nil, lookupErr
		}

		theme.Redf("[-] No public commit emails found for %s", query).Fprintln(ghc.out)
		return nil, nil
	}

	sortedEmails := make([]string, 0, len(emails))
	for email := range emails {
		sortedEmails = append(sortedEmails, email)
	}
	slices.Sort(sortedEmails)

	var buffer strings.Builder

	incomplete := ""
	if lookupErr != nil {
		incomplete = " (incomplete, lookup stopped early)"
	}

	theme.Greenf("[+] Found %d email(s) in public commits%s:", len(emails), incomplete).Fprintln(ghc.out)
	fmt.Fprintf(&buffer, "[+] Found %d email(s) in public commits%s:\n", len(emails), incomplete)

	for index, email := range sortedEmails {
		info := email
		if name := emails[email]; name != "" {
			info = fmt.Sprintf("%s (%s)", email, name)
		}

		theme.Greenf(":: %03d :: %s", index+1, info).Fprintln(ghc.out)
		fmt.Fprintf(&buffer, ":: %03d :: %s\n", index+1, info)
	}

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Fprintln(ghc.out)
	}

	return emails, lookupErr
}

func (ghc *gitHubClient) buildEventRequest(ctx context.Context, query string) ([]gitHubEventResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/events/public", url.PathEscape(query))

	response, err := modules.FetchJSON[[]gitHubEventResponse](ctx, ghc.httpClient, endpoint, ghc.headers())
	if err != nil {
		return nil, fmt.Errorf("%s(buildEventRequest): %w", ghc.Name(), err)
	}

	return *response, nil
}

func (ghc *gitHubClient) buildCommitRequest(ctx context.Context, repo, sha string) (*gitHubCommitResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repo, sha)

	response, err := modules.FetchJSON[gitHubCommitResponse](ctx, ghc.httpClient, endpoint, ghc.headers())
	if err != nil {
		return nil, fmt.Errorf("%s(buildCommitRequest): %w", ghc.Name(), err)
	}

	return response, nil
}
