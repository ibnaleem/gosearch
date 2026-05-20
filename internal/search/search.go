package search

import (
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/olekukonko/tablewriter"

	"github.com/ibnaleem/gosearch/internal/config"
	github "github.com/ibnaleem/gosearch/internal/modules/github"
	"github.com/ibnaleem/gosearch/internal/models"
	"github.com/ibnaleem/gosearch/internal/theme"
	"github.com/ibnaleem/gosearch/internal/utils"
)

func SearchDomains(username string, domains []string, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{}
	theme.Yellow("[*] Searching ", len(domains), " domains with the username ", username, "...").Println()

	domainCount := 0
	table := tablewriter.NewWriter(os.Stdout)
	table.Header("NO", "DOMAIN", "STATUS")

	x := 0
	for _, domain := range domains {
		url := "http://" + domain

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			fmt.Printf("Error creating request for %s: %v\n", domain, err)
			continue
		}
		req.Header.Set("User-Agent", config.DefaultUserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Cache-Control", "max-age=0")

		resp, err := client.Do(req)
		if err != nil {
			var netErr net.Error
			ok := errors.As(err, &netErr)
			noSuchHostError := strings.Contains(err.Error(), "no such host")
			networkTimeoutError := ok && netErr.Timeout()

			if !noSuchHostError && !networkTimeoutError {
				fmt.Printf("Error sending request for %s: %v\n", domain, err)
			}
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			x++
			table.Append(x, domain, theme.Green(http.StatusOK))
			utils.WriteToFile(username, "[+] 200 OK: "+domain)
			domainCount++
		}
	}

	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}
	if domainCount > 0 {
		theme.Greenf("[+] Found %d domains with the username %s", domainCount, username).Println()
		utils.WriteToFile(username, "[+] Found "+strconv.Itoa(domainCount)+" domains with the username: "+username)
	} else {
		theme.Redf("[-] No domains found with the username %s", username).Println()
		utils.WriteToFile(username, "[-] No domains found with the username: "+username)
	}
}

func newHTTPClient(followRedirects bool) *http.Client {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: config.TLSConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Jar: nil,
	}
	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

func buildRequest(website models.Website, url string) (*http.Request, error) {
	userAgent := config.DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")

	for _, cookie := range website.Cookies {
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}

	return req, nil
}

func decodeBody(res *http.Response) (io.ReadCloser, error) {
	switch res.Header.Get("Content-Encoding") {
	case "gzip":
		return gzip.NewReader(res.Body)
	case "deflate":
		return zlib.NewReader(res.Body)
	case "br":
		return io.NopCloser(brotli.NewReader(res.Body)), nil
	default:
		return res.Body, nil
	}
}

func MakeRequestWithResponseURL(website models.Website, url string, username string) {
	client := newHTTPClient(website.FollowRedirects)

	req, err := buildRequest(website, url)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithResponseURL: %v\n", err)
		return
	}

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return
	}

	formattedResponseURL := utils.BuildURL(website.ResponseURL, username)
	if res.Request.URL.String() != formattedResponseURL {
		url = utils.BuildURL(website.BaseURL, username)
		theme.Green("[+]", website.Name, ":", url).Println()
		utils.WriteToFile(username, url+"\n")
		config.Count.Add(1)
	}
}

func MakeRequestWithErrorCode(website models.Website, url string, username string) {
	client := newHTTPClient(website.FollowRedirects)

	req, err := buildRequest(website, url)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorCode: %v\n", err)
		return
	}

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return
	}

	if res.StatusCode != website.ErrorCode {
		url = utils.BuildURL(website.BaseURL, username)
		theme.Green("[+] ", website.Name, ":", url).Println()
		utils.WriteToFile(username, url+"\n")
		config.Count.Add(1)
	}
}

func MakeRequestWithErrorMsg(website models.Website, url string, username string) {
	client := newHTTPClient(website.FollowRedirects)

	req, err := buildRequest(website, url)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorMsg: %v\n", err)
		return
	}

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	reader, err := decodeBody(res)
	if err != nil {
		fmt.Printf("Error decoding response body: %v\n", err)
		return
	}

	if res.StatusCode >= 400 {
		return
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	if !strings.Contains(string(body), website.ErrorMsg) {
		url = utils.BuildURL(website.BaseURL, username)
		theme.Green("[+] ", website.Name, ":", url).Println()
		utils.WriteToFile(username, url+"\n")
		config.Count.Add(1)
	}
}

func MakeRequestWithProfilePresence(website models.Website, url string, username string) {
	client := newHTTPClient(website.FollowRedirects)

	req, err := buildRequest(website, url)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithProfilePresence: %v\n", err)
		return
	}

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	if strings.Contains(string(body), website.ErrorMsg) {
		theme.Greenf("[+] %s: %s", website.Name, url).Println()
		utils.WriteToFile(username, url+"\n")
		config.Count.Add(1)
	}
}

func Search(data models.Data, username string, noFalsePositives bool, wg *sync.WaitGroup) {
	for _, website := range data.Websites {
		go func(website models.Website) {
			defer wg.Done()

			var url string
			if website.URLProbe != "" {
				url = utils.BuildURL(website.URLProbe, username)
			} else {
				url = utils.BuildURL(website.BaseURL, username)
			}

			if strings.TrimSpace(website.Name) == "GitHub" {
				githubUser, err := github.UnmarshalGitHubUser(username)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println()
				github.DisplayGitHubInfo(githubUser, username)
			}

			switch website.ErrorType {
			case "status_code":
				MakeRequestWithErrorCode(website, url, username)
			case "errorMsg":
				MakeRequestWithErrorMsg(website, url, username)
			case "profilePresence":
				MakeRequestWithProfilePresence(website, url, username)
			case "response_url":
				MakeRequestWithResponseURL(website, url, username)
			default:
				if !noFalsePositives {
					theme.Yellowf("[?] %s: %s", website.Name, url).Println()
					utils.WriteToFile(username, "[?] "+url+"\n")
					config.Count.Add(1)
				}
			}
		}(website)
	}
}
