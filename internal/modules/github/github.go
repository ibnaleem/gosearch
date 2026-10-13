package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/file"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/theme"
)

type gitHubClient struct {
	fileWriter *file.FileWriter
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

func NewGitHubClient(fileWriter *file.FileWriter) modules.Module {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: config.TLSConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	return &gitHubClient{
		fileWriter: fileWriter,
		httpClient: httpClient,
	}
}

func (ghc *gitHubClient) Name() string {
	return "Github"
}

func (ghc *gitHubClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	user, err := ghc.searchUser(ctx, query)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, nil
	}

	socialProfile, err := ghc.searchSocialProfile(ctx, query)
	if err != nil {
		return nil, err
	}

	sshKeys, err := ghc.searchSSHKeys(ctx, query)
	if err != nil {
		return nil, err
	}

	gpgKeys, err := ghc.searchGPGKey(ctx, query)
	if err != nil {
		return nil, err
	}

	mutualFollowers, err := ghc.searchMutualFollowers(ctx, query)
	if err != nil {
		return nil, err
	}

	emails, err := ghc.searchEmailFromCommits(ctx, query)
	if err != nil {
		return nil, err
	}

	result := modules.Result{
		Module: ghc.Name(),
		Summary: fmt.Sprintf(
			"1 profile found, %d social account(s), %d SSH key(s), %d GPG key(s), %d mutual follower(s), %d commit email(s)",
			len(socialProfile), len(sshKeys), len(gpgKeys), len(mutualFollowers), len(emails),
		),
	}

	return &result, nil
}

func (ghc *gitHubClient) searchUser(ctx context.Context, query string) (*gitHubUserResponse, error) {
	theme.Cyanf("[*] Searching %s on Github...", query).Println()
	response, err := ghc.buildUserRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if response.NodeID == "" {
		theme.Redf("[-] No Github profile found for %s", query).Println()
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] GitHub username found: %s", query).Println()
	fmt.Fprintf(&buffer, "[+] GitHub username found: %s\n", query)

	theme.Greenf(":: %03d :: %-16s : %s", 1, "Created at", response.CreatedAt).Println()
	fmt.Fprintf(&buffer, ":: %03d :: %-16s : %s\n", 1, "Created at", response.CreatedAt)

	theme.Greenf("          %-16s : %s", "Updated at", response.UpdatedAt).Println()
	fmt.Fprintf(&buffer, "          %-16s : %s\n", "Updated at", response.UpdatedAt)

	if response.Name != "" {
		theme.Greenf("          %-16s : %s", "Name", response.Name).Println()
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Name", response.Name)
	}

	if response.Email != "" {
		theme.Greenf("          %-16s : %s", "Email", response.Email).Println()
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Email", response.Email)
	}

	if response.Location != "" {
		theme.Greenf("          %-16s : %s", "Current location", response.Location).Println()
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Current location", response.Location)
	}

	if response.Bio != "" {
		theme.Greenf("          %-16s : %s", "Bio", response.Bio).Println()
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Bio", response.Bio)
	}

	if response.Company != "" {
		theme.Greenf("          %-16s : %s", "Current company", response.Company).Println()
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Current company", response.Company)
	}

	if response.Blog != "" {
		theme.Greenf("          %-16s : %s", "Blog", response.Blog).Println()
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Blog", response.Blog)
	}

	if response.GravatarID != "" {
		theme.Greenf("          %-16s : %s", "Gravatar ID", response.GravatarID).Println()
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Gravatar ID", response.GravatarID)
	}

	if response.TwitterUsername != "" {
		theme.Greenf("          %-16s : %s", "Twitter username", response.TwitterUsername).Println()
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Twitter username", response.TwitterUsername)
	}

	if response.AvatarURL != "" {
		theme.Greenf("          %-16s : %s", "Avatar URL", response.AvatarURL).Println()
		fmt.Fprintf(&buffer, "          %-16s : %s\n", "Avatar URL", response.AvatarURL)
	}

	theme.Greenf("          %-16s : %d", "Public repos", response.PublicRepos).Println()
	theme.Greenf("          %-16s : %d", "Public gists", response.PublicGists).Println()
	theme.Greenf("          %-16s : %d", "Followers", response.Followers).Println()
	theme.Greenf("          %-16s : %d", "Following", response.Following).Println()
	theme.Greenf("          %-16s : %s", "Node ID", response.NodeID).Println()

	fmt.Fprintf(&buffer, "          %-16s : %d\n", "Public repos", response.PublicRepos)
	fmt.Fprintf(&buffer, "          %-16s : %d\n", "Public gists", response.PublicGists)
	fmt.Fprintf(&buffer, "          %-16s : %d\n", "Followers", response.Followers)
	fmt.Fprintf(&buffer, "          %-16s : %d\n", "Following", response.Following)
	fmt.Fprintf(&buffer, "          %-16s : %s\n", "Node ID", response.NodeID)

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return response, nil
}

func (ghc *gitHubClient) buildUserRequest(ctx context.Context, param any) (*gitHubUserResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildUserRequest): create request: %w", ghc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := ghc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildUserRequest): send request: %w", ghc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(ghc.Name(), "buildUserRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildUserRequest): read response: %w", ghc.Name(), err)
	}

	var gitHubUserResponse gitHubUserResponse
	if err := json.Unmarshal(body, &gitHubUserResponse); err != nil {
		return nil, fmt.Errorf("%s(buildUserRequest): decode response: %w", ghc.Name(), err)
	}

	return &gitHubUserResponse, nil
}

func (ghc *gitHubClient) searchSocialProfile(ctx context.Context, query string) ([]gitHubSocialAccountResponse, error) {
	theme.Cyanf("[*] Searching %s on Github for social accounts...", query).Println()

	response, err := ghc.buildSocialAccountRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		theme.Redf("[-] No social accounts found").Println()
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d social account(s):", len(response)).Println()
	fmt.Fprintf(&buffer, "[+] Found %d social account(s):\n", len(response))

	for index, account := range response {
		theme.Greenf(":: %03d :: %-10s : %s", index+1, account.Provider, account.URL).Println()
		fmt.Fprintf(&buffer, ":: %03d :: %-10s : %s\n", index+1, account.Provider, account.URL)
	}

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return response, nil
}

func (ghc *gitHubClient) buildSocialAccountRequest(ctx context.Context, param any) ([]gitHubSocialAccountResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/social_accounts", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSocialAccountRequest): create request: %w", ghc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := ghc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSocialAccountRequest): send request: %w", ghc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(ghc.Name(), "buildSocialAccountRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSocialAccountRequest): read response: %w", ghc.Name(), err)
	}

	var gitHubSocialAccountResponses []gitHubSocialAccountResponse
	if err := json.Unmarshal(body, &gitHubSocialAccountResponses); err != nil {
		return nil, fmt.Errorf("%s(buildSocialAccountRequest): decode response: %w", ghc.Name(), err)
	}

	return gitHubSocialAccountResponses, nil
}

func (ghc *gitHubClient) searchSSHKeys(ctx context.Context, query string) ([]gitHubSSHKeyResponse, error) {
	theme.Cyanf("[*] Searching %s on Github for SSH keys...", query).Println()

	response, err := ghc.buildSSHKeyRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		theme.Redf("[-] No public SSH keys found for %s", query).Println()
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d SSH key(s):", len(response)).Println()
	fmt.Fprintf(&buffer, "[+] Found %d SSH key(s):\n", len(response))

	for index, key := range response {
		keyType := strings.SplitN(key.Key, " ", 2)[0]
		theme.Greenf(":: %03d :: %-10s : id %d", index+1, keyType, key.ID).Println()
		fmt.Fprintf(&buffer, ":: %03d :: %-10s : id %d\n", index+1, keyType, key.ID)
	}

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return response, nil
}

func (ghc *gitHubClient) buildSSHKeyRequest(ctx context.Context, param any) ([]gitHubSSHKeyResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/keys", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSSHKeyRequest): create request: %w", ghc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := ghc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSSHKeyRequest): send request: %w", ghc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(ghc.Name(), "buildSSHKeyRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSSHKeyRequest): read response: %w", ghc.Name(), err)
	}

	var gitHubSSHKeyResponses []gitHubSSHKeyResponse
	if err := json.Unmarshal(body, &gitHubSSHKeyResponses); err != nil {
		return nil, fmt.Errorf("%s(buildSSHKeyRequest): decode response: %w", ghc.Name(), err)
	}

	return gitHubSSHKeyResponses, nil
}

func (ghc *gitHubClient) searchGPGKey(ctx context.Context, query string) ([]gitHubGPGKeyResponse, error) {
	theme.Cyanf("[*] Searching %s on Github for GPG keys...", query).Println()

	response, err := ghc.buildGPGKeyRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		theme.Redf("[-] No public GPG keys found for %s", query).Println()
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d GPG key(s):", len(response)).Println()
	fmt.Fprintf(&buffer, "[+] Found %d GPG key(s):\n", len(response))

	for index, key := range response {
		info := key.KeyID
		if key.Name != "" {
			info = fmt.Sprintf("%s (%s)", key.KeyID, key.Name)
		}

		theme.Greenf(":: %03d :: %-11s : %s", index+1, "Fingerprint", info).Println()
		fmt.Fprintf(&buffer, ":: %03d :: %-11s : %s\n", index+1, "Fingerprint", info)

		for _, email := range key.Emails {
			verified := ""
			if email.Verified {
				verified = " (verified)"
			}

			theme.Greenf("          %-11s : %s%s", "Email", email.Email, verified).Println()
			fmt.Fprintf(&buffer, "          %-11s : %s%s\n", "Email", email.Email, verified)
		}

		if key.Revoked {
			theme.Yellowf("          %-11s : revoked", "Status").Println()
			fmt.Fprintf(&buffer, "          %-11s : revoked\n", "Status")
		}
	}

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return response, nil
}

func (ghc *gitHubClient) buildGPGKeyRequest(ctx context.Context, param any) ([]gitHubGPGKeyResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/gpg_keys", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildGPGKeyRequest): create request: %w", ghc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := ghc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildGPGKeyRequest): send request: %w", ghc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(ghc.Name(), "buildGPGKeyRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildGPGKeyRequest): read response: %w", ghc.Name(), err)
	}

	var gitHubGPGKeyResponses []gitHubGPGKeyResponse
	if err := json.Unmarshal(body, &gitHubGPGKeyResponses); err != nil {
		return nil, fmt.Errorf("%s(buildGPGKeyRequest): decode response: %w", ghc.Name(), err)
	}

	return gitHubGPGKeyResponses, nil
}

func (ghc *gitHubClient) searchMutualFollowers(ctx context.Context, query string) ([]string, error) {
	theme.Cyanf("[*] Searching %s on Github for mutual followers...", query).Println()

	followers, err := ghc.buildFollowersRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(followers) == 0 {
		theme.Redf("[-] No followers found for %s", query).Println()
		return nil, nil
	}

	mutualFollowers, err := ghc.buildMutualFollowersRequest(ctx, query, followers)
	if err != nil {
		return nil, err
	}

	if len(mutualFollowers) == 0 {
		theme.Redf("[-] No mutual followers found for %s", query).Println()
		return nil, nil
	}

	var buffer strings.Builder

	theme.Greenf("[+] Found %d mutual follower(s):", len(mutualFollowers)).Println()
	fmt.Fprintf(&buffer, "[+] Found %d mutual follower(s):\n", len(mutualFollowers))

	for index, follower := range mutualFollowers {
		theme.Greenf(":: %03d :: %s", index+1, follower).Println()
		fmt.Fprintf(&buffer, ":: %03d :: %s\n", index+1, follower)
	}

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return mutualFollowers, nil
}

func (ghc *gitHubClient) buildFollowersRequest(ctx context.Context, param any) ([]gitHubFollowersResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/followers?per_page=100", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildFollowersRequest): create request: %w", ghc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := ghc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildFollowersRequest): send request: %w", ghc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(ghc.Name(), "buildFollowersRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildFollowersRequest): read response: %w", ghc.Name(), err)
	}

	var gitHubFollowersResponses []gitHubFollowersResponse
	if err := json.Unmarshal(body, &gitHubFollowersResponses); err != nil {
		return nil, fmt.Errorf("%s(buildFollowersRequest): decode response: %w", ghc.Name(), err)
	}

	return gitHubFollowersResponses, nil
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

		if response.StatusCode == http.StatusNoContent {
			mutualFollowers = append(mutualFollowers, follower.Login)
		}

		response.Body.Close()
	}

	return mutualFollowers, nil
}

func (ghc *gitHubClient) searchEmailFromCommits(ctx context.Context, query string) (map[string]string, error) {
	theme.Cyanf("[*] Searching %s on Github for emails in public commits...", query).Println()

	events, err := ghc.buildEventRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	emails := make(map[string]string)
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if event.Type != "PushEvent" || event.Repo.Name == "" || event.Payload.Head == "" {
			continue
		}

		commit, err := ghc.buildCommitRequest(ctx, event.Repo.Name, event.Payload.Head)
		if err != nil {
			continue
		}

		author := commit.Commit.Author
		if author.Email == "" || strings.Contains(author.Email, "noreply.github.com") {
			continue
		}

		emails[author.Email] = author.Name
	}

	if len(emails) == 0 {
		theme.Redf("[-] No public commit emails found for %s", query).Println()
		return nil, nil
	}

	sortedEmails := make([]string, 0, len(emails))
	for email := range emails {
		sortedEmails = append(sortedEmails, email)
	}
	slices.Sort(sortedEmails)

	var buffer strings.Builder

	theme.Greenf("[+] Found %d email(s) in public commits:", len(emails)).Println()
	fmt.Fprintf(&buffer, "[+] Found %d email(s) in public commits:\n", len(emails))

	for index, email := range sortedEmails {
		info := email
		if name := emails[email]; name != "" {
			info = fmt.Sprintf("%s (%s)", email, name)
		}

		theme.Greenf(":: %03d :: %s", index+1, info).Println()
		fmt.Fprintf(&buffer, ":: %03d :: %s\n", index+1, info)
	}

	if err := ghc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return emails, nil
}

func (ghc *gitHubClient) buildEventRequest(ctx context.Context, param any) ([]gitHubEventResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/events/public", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildEventRequest): create request: %w", ghc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := ghc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildEventRequest): send request: %w", ghc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(ghc.Name(), "buildEventRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildEventRequest): read response: %w", ghc.Name(), err)
	}

	var gitHubEventResponses []gitHubEventResponse
	if err := json.Unmarshal(body, &gitHubEventResponses); err != nil {
		return nil, fmt.Errorf("%s(buildEventRequest): decode response: %w", ghc.Name(), err)
	}

	return gitHubEventResponses, nil
}

func (ghc *gitHubClient) buildCommitRequest(ctx context.Context, repo, sha string) (*gitHubCommitResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repo, sha)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildCommitRequest): create request: %w", ghc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := ghc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildCommitRequest): send request: %w", ghc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(ghc.Name(), "buildCommitRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildCommitRequest): read response: %w", ghc.Name(), err)
	}

	var gitHubCommitResponse gitHubCommitResponse
	if err := json.Unmarshal(body, &gitHubCommitResponse); err != nil {
		return nil, fmt.Errorf("%s(buildCommitRequest): decode response: %w", ghc.Name(), err)
	}

	return &gitHubCommitResponse, nil
}
