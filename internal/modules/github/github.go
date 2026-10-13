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

type githubClient struct {
	fileWriter *file.FileWriter
	httpClient *http.Client
}

type githubUserResponse struct {
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

type githubSocialAccountResponse struct {
	Provider string `json:"provider"`
	URL      string `json:"url"`
}

type githubSSHKeyResponse struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
}

type githubGPGKeyResponse struct {
	Name      string           `json:"name"`
	KeyID     string           `json:"key_id"`
	Emails    []githubGPGEmail `json:"emails"`
	CreatedAt string           `json:"created_at"`
	ExpiresAt *string          `json:"expires_at"`
	Revoked   bool             `json:"revoked"`
}

type githubGPGEmail struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

type githubFollowersResponse struct {
	Login string `json:"login"`
}

type githubEventResponse struct {
	Type    string            `json:"type"`
	Repo    githubEventRepo   `json:"repo"`
	Payload githubPushPayload `json:"payload"`
}

type githubEventRepo struct {
	Name string `json:"name"`
}

type githubPushPayload struct {
	Head string `json:"head"`
}

type githubCommitResponse struct {
	Commit githubCommitDetail `json:"commit"`
}

type githubCommitDetail struct {
	Author  githubCommitAuthor `json:"author"`
	Message string             `json:"message"`
}

type githubCommitAuthor struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

func NewGithubClient(fileWriter *file.FileWriter) modules.Module {
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

	return &githubClient{
		fileWriter: fileWriter,
		httpClient: httpClient,
	}
}

func (gc *githubClient) Name() string {
	return "Github"
}

func (gc *githubClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	user, err := gc.searchUser(ctx, query)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, nil
	}

	socialProfile, err := gc.searchSocialProfile(ctx, query)
	if err != nil {
		return nil, err
	}

	sshKeys, err := gc.searchSSHKeys(ctx, query)
	if err != nil {
		return nil, err
	}

	gpgKeys, err := gc.searchGPGKey(ctx, query)
	if err != nil {
		return nil, err
	}

	mutualFollowers, err := gc.searchMutualFollowers(ctx, query)
	if err != nil {
		return nil, err
	}

	emails, err := gc.searchEmailFromCommits(ctx, query)
	if err != nil {
		return nil, err
	}

	result := modules.Result{
		Module: gc.Name(),
		Summary: fmt.Sprintf(
			"1 profile found, %d social account(s), %d SSH key(s), %d GPG key(s), %d mutual follower(s), %d commit email(s)",
			len(socialProfile), len(sshKeys), len(gpgKeys), len(mutualFollowers), len(emails),
		),
	}

	return &result, nil
}

func (gc *githubClient) searchUser(ctx context.Context, query string) (*githubUserResponse, error) {
	theme.Cyanf("[*] Searching %s on Github...", query).Println()
	response, err := gc.buildUserRequest(ctx, query)
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

	if err := gc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return response, nil
}

func (gc *githubClient) buildUserRequest(ctx context.Context, param any) (*githubUserResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildUserRequest): create request: %w", gc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := gc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildUserRequest): send request: %w", gc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(gc.Name(), "buildUserRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildUserRequest): read response: %w", gc.Name(), err)
	}

	var githubUserResponse githubUserResponse
	if err := json.Unmarshal(body, &githubUserResponse); err != nil {
		return nil, fmt.Errorf("%s(buildUserRequest): decode response: %w", gc.Name(), err)
	}

	return &githubUserResponse, nil
}

func (gc *githubClient) searchSocialProfile(ctx context.Context, query string) ([]githubSocialAccountResponse, error) {
	theme.Cyanf("[*] Searching %s on Github for social accounts...", query).Println()

	response, err := gc.buildSocialAccountRequest(ctx, query)
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

	if err := gc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return response, nil
}

func (gc *githubClient) buildSocialAccountRequest(ctx context.Context, param any) ([]githubSocialAccountResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/social_accounts", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSocialAccountRequest): create request: %w", gc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := gc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSocialAccountRequest): send request: %w", gc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(gc.Name(), "buildSocialAccountRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSocialAccountRequest): read response: %w", gc.Name(), err)
	}

	var githubSocialAccountResponses []githubSocialAccountResponse
	if err := json.Unmarshal(body, &githubSocialAccountResponses); err != nil {
		return nil, fmt.Errorf("%s(buildSocialAccountRequest): decode response: %w", gc.Name(), err)
	}

	return githubSocialAccountResponses, nil
}

func (gc *githubClient) searchSSHKeys(ctx context.Context, query string) ([]githubSSHKeyResponse, error) {
	theme.Cyanf("[*] Searching %s on Github for SSH keys...", query).Println()

	response, err := gc.buildSSHKeyRequest(ctx, query)
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

	if err := gc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return response, nil
}

func (gc *githubClient) buildSSHKeyRequest(ctx context.Context, param any) ([]githubSSHKeyResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/keys", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSSHKeyRequest): create request: %w", gc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := gc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSSHKeyRequest): send request: %w", gc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(gc.Name(), "buildSSHKeyRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildSSHKeyRequest): read response: %w", gc.Name(), err)
	}

	var githubSSHKeyResponses []githubSSHKeyResponse
	if err := json.Unmarshal(body, &githubSSHKeyResponses); err != nil {
		return nil, fmt.Errorf("%s(buildSSHKeyRequest): decode response: %w", gc.Name(), err)
	}

	return githubSSHKeyResponses, nil
}

func (gc *githubClient) searchGPGKey(ctx context.Context, query string) ([]githubGPGKeyResponse, error) {
	theme.Cyanf("[*] Searching %s on Github for GPG keys...", query).Println()

	response, err := gc.buildGPGKeyRequest(ctx, query)
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

	if err := gc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return response, nil
}

func (gc *githubClient) buildGPGKeyRequest(ctx context.Context, param any) ([]githubGPGKeyResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/gpg_keys", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildGPGKeyRequest): create request: %w", gc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := gc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildGPGKeyRequest): send request: %w", gc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(gc.Name(), "buildGPGKeyRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildGPGKeyRequest): read response: %w", gc.Name(), err)
	}

	var githubGPGKeyResponses []githubGPGKeyResponse
	if err := json.Unmarshal(body, &githubGPGKeyResponses); err != nil {
		return nil, fmt.Errorf("%s(buildGPGKeyRequest): decode response: %w", gc.Name(), err)
	}

	return githubGPGKeyResponses, nil
}

func (gc *githubClient) searchMutualFollowers(ctx context.Context, query string) ([]string, error) {
	theme.Cyanf("[*] Searching %s on Github for mutual followers...", query).Println()

	followers, err := gc.buildFollowersRequest(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(followers) == 0 {
		theme.Redf("[-] No followers found for %s", query).Println()
		return nil, nil
	}

	mutualFollowers, err := gc.buildMutualFollowersRequest(ctx, query, followers)
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

	if err := gc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return mutualFollowers, nil
}

func (gc *githubClient) buildFollowersRequest(ctx context.Context, param any) ([]githubFollowersResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/followers?per_page=100", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildFollowersRequest): create request: %w", gc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := gc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildFollowersRequest): send request: %w", gc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(gc.Name(), "buildFollowersRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildFollowersRequest): read response: %w", gc.Name(), err)
	}

	var githubFollowersResponses []githubFollowersResponse
	if err := json.Unmarshal(body, &githubFollowersResponses); err != nil {
		return nil, fmt.Errorf("%s(buildFollowersRequest): decode response: %w", gc.Name(), err)
	}

	return githubFollowersResponses, nil
}

func (gc *githubClient) buildMutualFollowersRequest(ctx context.Context, query string, param []githubFollowersResponse) ([]string, error) {
	var mutualFollowers []string

	for _, follower := range param {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		endpoint := fmt.Sprintf("https://api.github.com/users/%s/following/%s", url.PathEscape(query), url.PathEscape(follower.Login))

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("%s(buildMutualFollowersRequest): create request: %w", gc.Name(), err)
		}

		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		}

		request.Header.Set("User-Agent", config.DefaultUserAgent)
		request.Header.Set("Accept", "application/vnd.github+json")

		response, err := gc.httpClient.Do(request)
		if err != nil {
			return nil, fmt.Errorf("%s(buildMutualFollowersRequest): send request: %w", gc.Name(), err)
		}

		if response.StatusCode == http.StatusNoContent {
			mutualFollowers = append(mutualFollowers, follower.Login)
		}

		response.Body.Close()
	}

	return mutualFollowers, nil
}

func (gc *githubClient) searchEmailFromCommits(ctx context.Context, query string) (map[string]string, error) {
	theme.Cyanf("[*] Searching %s on Github for emails in public commits...", query).Println()

	events, err := gc.buildEventRequest(ctx, query)
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

		commit, err := gc.buildCommitRequest(ctx, event.Repo.Name, event.Payload.Head)
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

	if err := gc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	return emails, nil
}

func (gc *githubClient) buildEventRequest(ctx context.Context, param any) ([]githubEventResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s/events/public", url.PathEscape(fmt.Sprint(param)))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildEventRequest): create request: %w", gc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := gc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildEventRequest): send request: %w", gc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(gc.Name(), "buildEventRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildEventRequest): read response: %w", gc.Name(), err)
	}

	var githubEventResponses []githubEventResponse
	if err := json.Unmarshal(body, &githubEventResponses); err != nil {
		return nil, fmt.Errorf("%s(buildEventRequest): decode response: %w", gc.Name(), err)
	}

	return githubEventResponses, nil
}

func (gc *githubClient) buildCommitRequest(ctx context.Context, repo, sha string) (*githubCommitResponse, error) {
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repo, sha)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s(buildCommitRequest): create request: %w", gc.Name(), err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := gc.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s(buildCommitRequest): send request: %w", gc.Name(), err)
	}

	defer response.Body.Close()

	if err := modules.CheckStatus(gc.Name(), "buildCommitRequest", response.StatusCode); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s(buildCommitRequest): read response: %w", gc.Name(), err)
	}

	var githubCommitResponse githubCommitResponse
	if err := json.Unmarshal(body, &githubCommitResponse); err != nil {
		return nil, fmt.Errorf("%s(buildCommitRequest): decode response: %w", gc.Name(), err)
	}

	return &githubCommitResponse, nil
}
