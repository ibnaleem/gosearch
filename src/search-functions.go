// All Search functions in GoSearch

package main

import (
	"io"
	"os"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
	"errors"
	"strconv"
	"strings"
	"net/http"
	"compress/gzip"
	"compress/zlib"
	
	"github.com/andybalholm/brotli"
	"github.com/olekukonko/tablewriter"
)

func SearchDomains(username string, domains []string, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{}
	Yellow("[*] Searching ", len(domains), " domains with the username ", username, "...").Println()

	domainCount := 0
	table := tablewriter.NewWriter(os.Stdout)
	table.Header("NO", "DOMAIN", "STATUS")

	// Counter for table rows
	x := 0
	for _, domain := range domains {
		url := "http://" + domain

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			fmt.Printf("Error creating request for %s: %v\n", domain, err)
			continue
		}
		req.Header.Set("User-Agent", DefaultUserAgent)
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
			x++ // increase table rows
			table.Append(x, domain, Green(http.StatusOK))
			WriteToFile(username, "[+] 200 OK: "+domain)
			domainCount++
		}
	}

	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}
	if domainCount > 0 {
		Greenf("[+] Found %d domains with the username %s", domainCount, username).Println()
		WriteToFile(username, "[+] Found "+strconv.Itoa(domainCount)+" domains with the username: "+username)
	} else {
		Redf("[-] No domains found with the username %s", username).Println()
		WriteToFile(username, "[-] No domains found with the username: "+username)
	}
}

func MakeRequestWithResponseURL(website Website, url string, username string) {
	// Some websites always return a 200 for existing and non-existing profiles.
	// If we do not follow redirects, we could get a 301 for existing profiles and 302 for non-existing profiles.
	// That is why we have the follow_redirects in our website struct.
	// However, sometimes the website returns 301 for existing profiles and non-existing profiles.
	// This means even if we do not follow redirects, we still get false positives.
	// To mitigate this, we can examine the response url to check for non-existing profiles.
	// Usually, a response url pointing to where the profile should be is returned for existing profiles.
	// If the response url is not pointing to where the profile should be, then the profile does not exist.

	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
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

	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithResponseURL: %v\n", err)
		return
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

	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
	}

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return
	}

	formattedResponseURL := BuildURL(website.ResponseURL, username)
	if !(res.Request.URL.String() == formattedResponseURL) {
		url = BuildURL(website.BaseURL, username)
		Green("[+]", website.Name, ":", url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

func MakeRequestWithErrorCode(website Website, url string, username string) {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
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

	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorCode: %v\n", err)
		return
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

	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
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
		url = BuildURL(website.BaseURL, username)
		Green("[+] ", website.Name, ":", url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

func MakeRequestWithErrorMsg(website Website, url string, username string) {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
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

	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorMsg: %v\n", err)
		return
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

	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
	}

	res, err := client.Do(req)
	if err != nil {
		return
	}
	var reader io.ReadCloser
	switch res.Header.Get("Content-Encoding") {
	case "gzip":
		gzReader, err := gzip.NewReader(res.Body)
		if err != nil {
			fmt.Printf("Error creating gzip reader: %v\n", err)
			return
		}
		reader = gzReader
	case "deflate":
		zlibReader, err := zlib.NewReader(res.Body)
		if err != nil {
			fmt.Printf("Error creating deflate reader: %v\n", err)
			return
		}
		reader = zlibReader
	case "br":
		reader = io.NopCloser(brotli.NewReader(res.Body))
	default:
		reader = res.Body
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, website.ErrorMsg) {
		url = BuildURL(website.BaseURL, username)
		Green("[+] ", website.Name, ":", url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

func MakeRequestWithProfilePresence(website Website, url string, username string) {
	// Some websites have an indicator that a profile exists
	// but do not have an indicator when a profile does not exist.
	// If a profile indicator is not found, we can assume that the profile does not exist.

	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
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

	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("Error creating request in function MakeRequestWithErrorMsg: %v\n", err)
		return
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

	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			cookieObj := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			req.AddCookie(cookieObj)
		}
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

	bodyStr := string(body)
	if strings.Contains(bodyStr, website.ErrorMsg) {
		Greenf("[+] %s: %s", website.Name, url).Println()
		WriteToFile(username, url+"\n")
		count.Add(1)
	}
}

func Search(data Data, username string, noFalsePositives bool, wg *sync.WaitGroup) {
	for _, website := range data.Websites {
		go func(website Website) {
			var url string
			defer wg.Done()

			if website.URLProbe != "" {
				url = BuildURL(website.URLProbe, username)
			} else {
				url = BuildURL(website.BaseURL, username)
			}

			if strings.TrimSpace(website.Name) == "GitHub" {

				
				githubUser, err := UnmarshalGitHubUser(username)
				
				if err != nil {
					log.Fatal(err)
				}

				fmt.Println()

				DisplayGitHubInfo(githubUser, username)
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
					Yellowf("[?] %s: %s", website.Name, url).Println()
					WriteToFile(username, "[?] "+url+"\n")
					count.Add(1)
				}
			}
		}(website)
	}
}