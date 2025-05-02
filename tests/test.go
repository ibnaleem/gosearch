package main

import (
	"bufio"
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/bytedance/sonic"
)

// Color output constants.
const (
	Red    = "\033[31m"
	Reset  = "\033[0m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
)

// User-Agent header used in requests.
const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"

var tlsConfig = &tls.Config{
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	},
	CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	NextProtos:       []string{"http/1.1"},
}

type Website struct {
	Name            string   `json:"name"`
	BaseURL         string   `json:"base_url"`
	URLProbe        string   `json:"url_probe,omitempty"`
	FollowRedirects bool     `json:"follow_redirects,omitempty"`
	UserAgent       string   `json:"user_agent,omitempty"`
	ErrorType       string   `json:"errorType"`
	ErrorMsg        string   `json:"errorMsg,omitempty"`
	ErrorCode       int      `json:"errorCode,omitempty"`
	ResponseURL     string   `json:"response_url,omitempty"`
	Cookies         []Cookie `json:"cookies,omitempty"`
}

type Data struct {
	Websites []Website `json:"websites"`
}

type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func UnmarshalJSON() (Data, error) {
	err := os.Remove("data.json")
	if err != nil && !os.IsNotExist(err) {
		return Data{}, fmt.Errorf("error deleting old data.json: %w", err)
	}

	url := "https://raw.githubusercontent.com/ibnaleem/gosearch/refs/heads/main/data.json"
	resp, err := http.Get(url)
	if err != nil {
		return Data{}, fmt.Errorf("error downloading data.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Data{}, fmt.Errorf("failed to download data.json, status code: %d", resp.StatusCode)
	}

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return Data{}, fmt.Errorf("error reading downloaded content: %w", err)
	}

	var data Data
	err = sonic.Unmarshal(jsonData, &data)
	if err != nil {
		return Data{}, fmt.Errorf("error unmarshalling JSON: %w", err)
	}

	return data, nil
}

func Mode0(url string) error {
	fmt.Println(Yellow+"[*] Testing URL:", url+Reset)
	fmt.Println(Yellow + "[*] Mode: 0 (Status Code)" + Reset)

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
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request failed: %w", err)
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()

	fmt.Println(Green+"[+] Response:", res.Status+Reset)
	fmt.Println(Green+"[+] Response URL:", res.Request.URL.String()+Reset)
	return nil
}

func Mode1(url string) error {
	fmt.Println(Yellow+"[*] Testing URL:", url+Reset)
	fmt.Println(Yellow + "[*] Mode: 1 (Response Body)" + Reset)

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
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request failed: %w", err)
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return fmt.Errorf("received error status: %s", res.Status)
	}

	var reader io.ReadCloser
	switch res.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(res.Body)
	case "deflate":
		reader, err = zlib.NewReader(res.Body)
	case "br":
		reader = io.NopCloser(brotli.NewReader(res.Body))
	default:
		reader = res.Body
	}

	if err != nil {
		return fmt.Errorf("decompression error: %w", err)
	}
	defer reader.Close()

	body, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("reading body failed: %w", err)
	}

	err = os.WriteFile("response.txt", body, os.ModePerm)
	if err != nil {
		return fmt.Errorf("writing to file failed: %w", err)
	}

	fmt.Println(Green + "[+] Response saved to response.txt" + Reset)
	return nil
}

func Mode2(url string) error {
	fmt.Println(Yellow+"[*] Testing URL:", url+Reset)
	fmt.Println(Yellow + "[*] Mode: 2 (Status Code Without Following Redirects)" + Reset)

	client := &http.Client{
		Timeout: 85 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request failed: %w", err)
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()

	fmt.Println(Green+"[+] Response:", res.Status+Reset)
	fmt.Println(Green+"[+] Response URL:", res.Request.URL.String()+Reset)
	return nil
}

func Mode3(url string) error {
	fmt.Println(Yellow+"[*] Testing URL:", url+Reset)
	fmt.Println(Yellow + "[*] Mode: 3 (Response Body Without Following Redirects)" + Reset)

	client := &http.Client{
		Timeout: 85 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request failed: %w", err)
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()

	var reader io.ReadCloser
	switch res.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(res.Body)
	case "deflate":
		reader, err = zlib.NewReader(res.Body)
	case "br":
		reader = io.NopCloser(brotli.NewReader(res.Body))
	default:
		reader = res.Body
	}

	if err != nil {
		return fmt.Errorf("decompression error: %w", err)
	}
	defer reader.Close()

	body, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("reading body failed: %w", err)
	}

	err = os.WriteFile("response.txt", body, os.ModePerm)
	if err != nil {
		return fmt.Errorf("writing to file failed: %w", err)
	}

	fmt.Println(Green + "[+] Response saved to response.txt" + Reset)
	return nil
}

func main() {
	url := "https://example.com"

	if err := Mode0(url); err != nil {
		log.Println(Red+"Mode0 Error:", err, Reset)
	}
	if err := Mode1(url); err != nil {
		log.Println(Red+"Mode1 Error:", err, Reset)
	}
	if err := Mode2(url); err != nil {
		log.Println(Red+"Mode2 Error:", err, Reset)
	}
	if err := Mode3(url); err != nil {
		log.Println(Red+"Mode3 Error:", err, Reset)
	}
}
