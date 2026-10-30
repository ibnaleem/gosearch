package search

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/file"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/theme"
)

type searchClient struct {
	fileWriter           *file.FileWriter
	httpClient           *http.Client
	noRedirectHTTPClient *http.Client
	noFalsePositive      bool
}

type cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type website struct {
	Name            string   `json:"name"`
	BaseURL         string   `json:"base_url"`
	URLProbe        string   `json:"url_probe,omitempty"`
	FollowRedirects bool     `json:"follow_redirects"`
	UserAgent       string   `json:"user_agent,omitempty"`
	ErrorType       string   `json:"errorType"`
	ErrorMsg        string   `json:"errorMsg,omitempty"`
	ErrorCode       int      `json:"errorCode,omitempty"`
	ResponseURL     string   `json:"response_url,omitempty"`
	Cookies         []cookie `json:"cookies,omitempty"`
}

type resource struct {
	Websites []website `json:"websites"`
}

// probeTimeout caps one site check; the slowest live site measured answered
// in 8s, while a dead host otherwise holds the whole search for the 30s client timeout
var probeTimeout = 15 * time.Second

// a query used as a subdomain must be a single DNS label (RFC 1123)
var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func NewSearchClient(fileWriter *file.FileWriter, noFalsePositive bool) modules.Module {
	httpClient := config.NewHTTPClient()

	noRedirectHTTPClient := *httpClient
	noRedirectHTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &searchClient{
		fileWriter:           fileWriter,
		httpClient:           httpClient,
		noRedirectHTTPClient: &noRedirectHTTPClient,
		noFalsePositive:      noFalsePositive,
	}
}

func (sc *searchClient) Name() string {
	return "Search"
}

func (sc *searchClient) Search(ctx context.Context, query string) (*modules.Result, error) {
	domains, err := sc.searchDomain(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%s(searchDomain): search domain: %w", sc.Name(), err)
	}

	resources, err := sc.buildResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s(buildResources): %w", sc.Name(), err)
	}

	sites, uncertainSites, err := sc.searchSite(ctx, query, resources.Websites)
	if err != nil {
		return nil, fmt.Errorf("%s(searchSite): search site: %w", sc.Name(), err)
	}

	var buffer strings.Builder

	if len(domains) > 0 {
		fmt.Fprintf(&buffer, "[+] Found %d domains with the query %s\n", len(domains), query)
		for index, domain := range domains {
			fmt.Fprintf(&buffer, ":: %03d :: %s\n", index+1, domain)
		}
	}

	if len(sites) > 0 {
		fmt.Fprintf(&buffer, "[+] Found %d sites with the query %s\n", len(sites), query)
		for index, site := range sites {
			fmt.Fprintf(&buffer, ":: %03d :: %s\n", index+1, site)
		}
	}

	if len(uncertainSites) > 0 {
		fmt.Fprintf(&buffer, "[?] %d unverified sites with the query %s (manual check required)\n", len(uncertainSites), query)
		for index, site := range uncertainSites {
			fmt.Fprintf(&buffer, ":: %03d :: %s\n", index+1, site)
		}
	}

	if err := sc.fileWriter.Write(query, buffer.String()); err != nil {
		theme.Redf("[!] Could not write output file: %v", err).Println()
	}

	summary := fmt.Sprintf("%d domain(s), %d site(s) found", len(domains), len(sites))
	if len(uncertainSites) > 0 {
		summary += fmt.Sprintf(", %d unverified", len(uncertainSites))
	}

	result := modules.Result{
		Module:  sc.Name(),
		Summary: summary,
	}

	return &result, nil
}

func (sc *searchClient) searchDomain(ctx context.Context, query string) ([]string, error) {
	domains, err := sc.buildDomains(query)
	if err != nil {
		return nil, err
	}

	theme.Cyanf("[*] Searching %d domain(s) for %s...", len(domains), query).Println()

	var (
		mu sync.Mutex
		wg sync.WaitGroup

		foundDomains []string
	)

	for _, domain := range domains {
		wg.Go(func() {
			// most sites redirect http to https, so try https first and fall
			// back to http; a domain that doesn't respond is just not found
			var response *http.Response
			for _, scheme := range []string{"https", "http"} {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+domain, nil)
				if err != nil {
					return
				}

				request.Header.Set("User-Agent", config.DefaultUserAgent)
				request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
				request.Header.Set("Accept-Language", "en-US,en;q=0.5")
				request.Header.Set("Upgrade-Insecure-Requests", "1")
				request.Header.Set("Sec-Fetch-Dest", "document")
				request.Header.Set("Sec-Fetch-Mode", "navigate")
				request.Header.Set("Sec-Fetch-Site", "none")
				request.Header.Set("Sec-Fetch-User", "?1")
				request.Header.Set("Cache-Control", "max-age=0")

				response, err = sc.httpClient.Do(request)
				if err == nil {
					break
				}

				// a domain that doesn't resolve won't resolve over http either
				var dnsErr *net.DNSError
				if errors.As(err, &dnsErr) {
					return
				}
			}

			if response == nil {
				return
			}

			defer response.Body.Close()

			// count only a final 200 on the domain itself, so redirects to
			// parking pages, registrars or other sites don't count as found
			finalHost := response.Request.URL.Hostname()
			sameSite := finalHost == domain || finalHost == "www."+domain

			if response.StatusCode == http.StatusOK && sameSite {
				mu.Lock()
				foundDomains = append(foundDomains, domain)
				mu.Unlock()
			}
		})
	}

	wg.Wait()

	slices.Sort(foundDomains)

	if len(foundDomains) == 0 {
		theme.Redf("[-] No domains found with the query %s", query).Println()
		return nil, nil
	}

	theme.Greenf("[+] Found %d domains with the query %s", len(foundDomains), query).Println()

	for index, domain := range foundDomains {
		theme.Greenf(":: %03d :: %s", index+1, domain).Println()
	}

	return foundDomains, nil
}

func (sc *searchClient) buildDomains(field string) ([]string, error) {
	tlds := []string{
		".com", ".net", ".org", ".biz", ".info", ".name", ".pro", ".cat",
		".co", ".me", ".io", ".tech", ".dev", ".app", ".shop", ".fail",
		".xyz", ".blog", ".store", ".online", ".space", ".lol", ".fun",
		".social", ".ai", ".gg", ".tv", ".cc", ".site", ".website",
		".page", ".link", ".live", ".digital", ".cloud", ".email",
		".studio", ".design", ".art", ".life", ".world", ".news",
		".media", ".work", ".wiki", ".chat", ".cool", ".plus",
		".guru", ".ninja", ".rocks", ".wtf", ".us", ".uk", ".eu",
		".ca", ".de", ".fr", ".nl", ".in",
	}

	if field == "" {
		return nil, errors.New("at least one letter field is required")
	}

	// a domain name can't hold characters like '.', '/' or ' '
	if !dnsLabel.MatchString(field) {
		return nil, nil
	}

	var domains []string
	for _, tld := range tlds {
		domains = append(domains, fmt.Sprintf("%s%s", field, tld))
	}

	return domains, nil
}

// searchSite returns the sites where the query was found, and the sites with
// errorType "unknown" that can't be verified and need a manual check
func (sc *searchClient) searchSite(ctx context.Context, query string, sites []website) ([]string, []string, error) {
	theme.Cyanf("[*] Searching %d site(s) for %s...", len(sites), query).Println()

	var (
		mu sync.Mutex
		wg sync.WaitGroup

		foundSites     []string
		uncertainSites []string

		// sites that were rate-limited, failed server-side or timed out, so
		// they couldn't be checked; counted so they don't pass as "not found"
		failedProbes int
	)

	for _, site := range sites {
		wg.Go(func() {
			// query can't be a subdomain here (e.g. contains '.' or '/'), so the site can't host it
			if !sc.canBuildSiteURL(site.BaseURL, query) ||
				!sc.canBuildSiteURL(site.URLProbe, query) ||
				!sc.canBuildSiteURL(site.ResponseURL, query) {
				return
			}

			url, err := sc.buildSiteURL(site.BaseURL, query)
			if err != nil {
				theme.Redf("search: build site URL for %s: %v", site.Name, err).Println()
				return
			}

			if site.ErrorType == "unknown" {
				if !sc.noFalsePositive {
					mu.Lock()
					uncertainSites = append(uncertainSites, url)
					mu.Unlock()
				}

				return
			}

			probeURL := url
			if site.URLProbe != "" {
				probeURL, err = sc.buildSiteURL(site.URLProbe, query)
				if err != nil {
					theme.Redf("search: build probe URL for %s: %v", site.Name, err).Println()
					return
				}
			}

			probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()

			request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, probeURL, nil)
			if err != nil {
				theme.Redf("search: create request for %s: %v", probeURL, err).Println()
				return
			}

			userAgent := config.DefaultUserAgent
			if site.UserAgent != "" {
				userAgent = site.UserAgent
			}

			request.Header.Set("User-Agent", userAgent)
			request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			request.Header.Set("Accept-Language", "en-US,en;q=0.5")
			request.Header.Set("Upgrade-Insecure-Requests", "1")
			request.Header.Set("Sec-Fetch-Dest", "document")
			request.Header.Set("Sec-Fetch-Mode", "navigate")
			request.Header.Set("Sec-Fetch-Site", "none")
			request.Header.Set("Sec-Fetch-User", "?1")
			request.Header.Set("Cache-Control", "max-age=0")

			for _, cookie := range site.Cookies {
				request.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
			}

			httpClient := sc.httpClient
			if !site.FollowRedirects {
				httpClient = sc.noRedirectHTTPClient
			}

			response, err := httpClient.Do(request)
			if err != nil {
				if ctx.Err() == nil {
					mu.Lock()
					failedProbes++
					mu.Unlock()
				}

				return
			}

			defer response.Body.Close()

			if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError {
				mu.Lock()
				failedProbes++
				mu.Unlock()
				return
			}

			if response.StatusCode >= http.StatusBadRequest {
				return
			}

			var found bool
			switch site.ErrorType {
			case "status_code":
				found = response.StatusCode != site.ErrorCode

			case "errorMsg":
				body, err := io.ReadAll(response.Body)
				if err != nil {
					return
				}

				found = !strings.Contains(string(body), site.ErrorMsg)

			case "profilePresence":
				body, err := io.ReadAll(response.Body)
				if err != nil {
					return
				}

				found = strings.Contains(string(body), site.ErrorMsg)

			case "response_url":
				notFoundURL, err := sc.buildSiteURL(site.ResponseURL, query)
				if err != nil {
					return
				}

				found = response.Request.URL.String() != notFoundURL
			}

			if found {
				mu.Lock()
				foundSites = append(foundSites, url)
				mu.Unlock()
				return
			}
		})
	}

	wg.Wait()

	slices.Sort(foundSites)
	slices.Sort(uncertainSites)

	if failedProbes > 0 {
		theme.Yellowf("[!] %d site(s) could not be checked (rate limited, server error or timeout)", failedProbes).Println()
	}

	if len(foundSites) == 0 && len(uncertainSites) == 0 {
		theme.Redf("[-] No sites found with the query %s", query).Println()
		return nil, nil, nil
	}

	if len(foundSites) > 0 {
		theme.Greenf("[+] Found %d sites with the query %s", len(foundSites), query).Println()

		for index, site := range foundSites {
			theme.Greenf(":: %03d :: %s", index+1, site).Println()
		}
	}

	if len(uncertainSites) > 0 {
		theme.Yellowf("[?] %d unverified sites for the query %s (manual check required)", len(uncertainSites), query).Println()

		for index, site := range uncertainSites {
			theme.Yellowf(":: %03d :: %s", index+1, site).Println()
		}
	}

	return foundSites, uncertainSites, nil
}

func (sc *searchClient) buildResources(ctx context.Context) (*resource, error) {
	url := "https://raw.githubusercontent.com/ibnaleem/gosearch/refs/heads/main/data.json"

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("download data.json: %w", err)
	}

	// a network error and a non-200 response both fall back to the local copy
	response, err := sc.httpClient.Do(request)
	if err == nil {
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			err = fmt.Errorf("HTTP %d", response.StatusCode)
		}
	}

	var body []byte
	if err == nil {
		body, err = io.ReadAll(response.Body)
	} else {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		theme.Yellowf("[!] Failed to download data.json (%v), using local copy instead...", err).Println()
		body, err = os.ReadFile("data.json")
	}

	if err != nil {
		return nil, fmt.Errorf("read data.json: %w", err)
	}

	var searchResources resource
	if err := json.Unmarshal(body, &searchResources); err != nil {
		return nil, fmt.Errorf("decode data.json: %w", err)
	}

	return &searchResources, nil
}

// placeholderInHost reports whether {} sits in the hostname, e.g. https://{}.tumblr.com
func (sc *searchClient) placeholderInHost(baseURL string) bool {
	index := strings.Index(baseURL, "{}")
	if index < 0 {
		return false
	}

	hostStart := strings.Index(baseURL, "://") + len("://")
	hostEnd := strings.IndexAny(baseURL[hostStart:], "/?#")

	return hostEnd < 0 || index < hostStart+hostEnd
}

// canBuildSiteURL reports whether field can be safely put into baseURL.
// Path and query placeholders can always be escaped; hostnames cannot.
func (sc *searchClient) canBuildSiteURL(baseURL string, field string) bool {
	return !sc.placeholderInHost(baseURL) || dnsLabel.MatchString(field)
}

// buildSiteURL substitutes field into the {} placeholder, escaped for the
// part of the URL it lands in. Hostname placeholders are left raw, so
// callers must check canBuildSiteURL first.
func (sc *searchClient) buildSiteURL(baseURL string, field string) (string, error) {
	if field == "" {
		return "", errors.New("at least one letter field is required")
	}

	before, after, found := strings.Cut(baseURL, "{}")
	if !found {
		return baseURL, nil
	}

	escaped := field
	switch {
	case sc.placeholderInHost(baseURL):
	case strings.ContainsAny(before, "?#"):
		escaped = url.QueryEscape(field)
	default:
		escaped = url.PathEscape(field)
	}

	return before + escaped + after, nil
}
