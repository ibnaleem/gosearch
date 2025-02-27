package main

import (
    "net/http"
    "net/http/httptest"
    "os"
    "strings"
    "sync"
    "testing"
    "io/ioutil"
)

// TestBuildURL tests that BuildURL correctly replaces the placeholder with the username.
func TestBuildURL(t *testing.T) {
    base := "http://example.com/{}"
    username := "alice"
    expected := "http://example.com/alice"
    got := BuildURL(base, username)
    if got != expected {
    t.Errorf("BuildURL() = %s; want %s", got, expected)
    }
}

// TestBuildDomains tests that BuildDomains returns the expected number of domains and the first is correct.
func TestBuildDomains(t *testing.T) {
    username := "bob"
    domains := BuildDomains(username)
    expectedFirst := "bob.com"
    // We expect 26 TLDs as defined in gosearch.go
    if len(domains) != 26 {
    t.Errorf("BuildDomains() returned %d domains; want %d", len(domains), 26)
    }
    if domains[0] != expectedFirst {
    t.Errorf("BuildDomains()[0] = %s; want %s", domains[0], expectedFirst)
    }
}

// TestWriteAndDeleteFile tests that WriteToFile writes content properly and DeleteOldFile removes it.
func TestWriteAndDeleteFile(t *testing.T) {
    username := "testuser"
    // Ensure deletion of any pre-existing file.
    DeleteOldFile(username)
    fname := username + ".txt"
    if _, err := os.Stat(fname); err == nil {
    t.Fatalf("File %s should not exist", fname)
    }

    WriteToFile(username, "hello world\n")
    data, err := os.ReadFile(fname)
    if err != nil {
    t.Fatalf("Failed to read file %s: %v", fname, err)
    }
    if !strings.Contains(string(data), "hello world") {
    t.Errorf("File %s does not contain expected text", fname)
    }

    DeleteOldFile(username)
    if _, err := os.Stat(fname); err == nil {
    t.Errorf("File %s was not deleted", fname)
    }
}

// TestMakeRequestWithErrorMsg simulates a server response to test MakeRequestWithErrorMsg.
func TestMakeRequestWithErrorMsg(t *testing.T) {
    // Reset count for test isolation.
    count.Store(0)
    username := "testErrorMsg"
    DeleteOldFile(username)

    // Create test server that returns a simple body.
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(200)
    w.Write([]byte("profile exists"))
    }))
    defer ts.Close()

    website := Website{
    Name:            "TestErrorMsg",
    BaseURL:         ts.URL + "/{}",
    ErrorMsg:        "not found", // This text does not appear in the response text.
    FollowRedirects: false,
    }
    url := BuildURL(website.BaseURL, username)
    MakeRequestWithErrorMsg(website, url, username)

    // Verify that the URL is written to the file.
    fname := username + ".txt"
    content, err := os.ReadFile(fname)
    if err != nil {
    t.Fatalf("Failed reading file %s: %v", fname, err)
    }
    expectedURL := BuildURL(website.BaseURL, username)
    if !strings.Contains(string(content), expectedURL) {
    t.Errorf("Expected file to contain URL %s, got %s", expectedURL, string(content))
    }
    DeleteOldFile(username)
}

// TestMakeRequestWithProfilePresence simulates a response to test MakeRequestWithProfilePresence.
func TestMakeRequestWithProfilePresence(t *testing.T) {
    count.Store(0)
    username := "testProfilePresence"
    DeleteOldFile(username)

    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(200)
    w.Write([]byte("profile indicator present"))
    }))
    defer ts.Close()

    website := Website{
    Name:            "TestProfilePresence",
    BaseURL:         ts.URL + "/{}",
    ErrorMsg:        "profile indicator present", // Should match the response body.
    FollowRedirects: false,
    }
    url := BuildURL(website.BaseURL, username)
    MakeRequestWithProfilePresence(website, url, username)

    fname := username + ".txt"
    content, err := os.ReadFile(fname)
    if err != nil {
    t.Fatalf("Failed reading file %s: %v", fname, err)
    }
    if !strings.Contains(string(content), url) {
    t.Errorf("Expected file to contain URL %s, got %s", url, string(content))
    }
    DeleteOldFile(username)
}

// TestMakeRequestWithResponseURL simulates a response to test MakeRequestWithResponseURL.
func TestMakeRequestWithResponseURL(t *testing.T) {
    count.Store(0)
    username := "testResponseURL"
    DeleteOldFile(username)

    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(200)
    w.Write([]byte("irrelevant body"))
    }))
    defer ts.Close()

    website := Website{
    Name:            "TestResponseURL",
    BaseURL:         ts.URL + "/profile/{}",
    ResponseURL:     ts.URL + "/different/{}", // This will differ from res.Request.URL after the request.
    FollowRedirects: false,
    }
    // Build URL using BaseURL since URLProbe is empty.
    url := BuildURL(website.BaseURL, username)
    MakeRequestWithResponseURL(website, url, username)

    fname := username + ".txt"
    content, err := os.ReadFile(fname)
    if err != nil {
    t.Fatalf("Failed reading file %s: %v", fname, err)
    }
    expected := BuildURL(website.BaseURL, username)
    if !strings.Contains(string(content), expected) {
    t.Errorf("Expected file to contain URL %s, got %s", expected, string(content))
    }
    DeleteOldFile(username)
}

// TestMakeRequestWithErrorCode simulates a response to test MakeRequestWithErrorCode.
func TestMakeRequestWithErrorCode(t *testing.T) {
    count.Store(0)
    username := "testErrorCode"
    DeleteOldFile(username)

    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(200)
    w.Write([]byte("OK"))
    }))
    defer ts.Close()

    website := Website{
    Name:            "TestErrorCode",
    BaseURL:         ts.URL + "/{}",
    ErrorCode:       404, // Expected error code does not match actual 200.
    FollowRedirects: false,
    }
    url := BuildURL(website.BaseURL, username)
    MakeRequestWithErrorCode(website, url, username)

    fname := username + ".txt"
    content, err := os.ReadFile(fname)
    if err != nil {
    t.Fatalf("Failed reading file %s: %v", fname, err)
    }
    expected := BuildURL(website.BaseURL, username)
    if !strings.Contains(string(content), expected) {
    t.Errorf("Expected file to contain URL %s, got %s", expected, string(content))
    }
    DeleteOldFile(username)
}

// TestSearchFalsePositive tests the Search function with a website that has an unknown error type.
func TestSearchFalsePositive(t *testing.T) {
    count.Store(0)
    username := "testSearchFalsePositive"
    DeleteOldFile(username)

    // Create a dummy website with an unknown ErrorType.
    website := Website{
    Name:            "UnknownTest",
    BaseURL:         "http://example.com/{}",
    ErrorType:       "unknown",
    FollowRedirects: false,
    }
    data := Data{
    Websites: []Website{website},
    }
    var wg sync.WaitGroup
    wg.Add(1)
    // Call Search with noFalsePositives flag set to false, so a false positive should be printed.
    Search(data, username, false, &wg)
    wg.Wait()

    fname := username + ".txt"
    content, err := os.ReadFile(fname)
    if err != nil {
    t.Fatalf("Failed reading file %s: %v", fname, err)
    }
    if !strings.Contains(string(content), "[?]") {
    t.Errorf("Expected file to contain false positive indicator '[?]', got %s", string(content))
    }
    DeleteOldFile(username)
// roundTripFunc is a helper type to allow monkey patching http.RoundTripper in tests.
}
type roundTripFunc func(req *http.Request) *http.Response

// RoundTrip executes a single HTTP transaction.
func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
    return f(req), nil
}

// TestCrackHash simulates a successful weakpass API call by intercepting the HTTP request and returning a fake response.
func TestCrackHash(t *testing.T) {
    // Backup the original transport and restore later.
    origTransport := http.DefaultTransport
    defer func() { http.DefaultTransport = origTransport }()

    // Inject our fake RoundTripper.
    http.DefaultTransport = roundTripFunc(func(req *http.Request) *http.Response {
        // Validate the request URL contains the weakpass path.
        if strings.Contains(req.URL.String(), "weakpass.com/api/v1/search/") {
            // Construct a fake JSON response returning a password of "fakepassword"
            body := `{"type": "test", "hash": "` + req.URL.Path[len("/api/v1/search/") : len(req.URL.Path)-len(".json")] + `", "pass": "fakepassword"}`
            return &http.Response{
                StatusCode: 200,
                Body:       ioutil.NopCloser(strings.NewReader(body)),
                Header:     make(http.Header),
            }
        }
        // Otherwise, return a 404 response.
        return &http.Response{
            StatusCode: 404,
            Body:       ioutil.NopCloser(strings.NewReader("")),
            Header:     make(http.Header),
        }
    })

    pass := CrackHash("dummyhash")
    if pass != "fakepassword" {
        t.Errorf("Expected fakepassword, got %s", pass)
    }
}

// TestSearchNoWebsites verifies that when Data.Websites is empty, a file is not created.
func TestSearchNoWebsites(t *testing.T) {
    username := "emptyTest"
    DeleteOldFile(username)
    data := Data{Websites: []Website{}}
    var wg sync.WaitGroup
    Search(data, username, false, &wg)
    wg.Wait()

    fname := username + ".txt"
    if _, err := os.Stat(fname); err == nil {
        t.Errorf("Expected no file created for empty websites but file %s exists", fname)
        DeleteOldFile(username)
    }
}

// TestSearchNoFalsePositives tests that when noFalsePositives is true, the false positive indicator "[?]" is not written to the file.
func TestSearchNoFalsePositives(t *testing.T) {
    username := "noFalsePositivesTest"
    DeleteOldFile(username)

    website := Website{
        Name:            "NoFalsePositives",
        BaseURL:         "http://example.com/{}",
        ErrorType:       "unknown",
        FollowRedirects: false,
    }
    data := Data{Websites: []Website{website}}

    var wg sync.WaitGroup
    wg.Add(1)
    // With noFalsePositives flag true, the Search function should not write a "[?]" false positive indicator.
    Search(data, username, true, &wg)
    wg.Wait()

    fname := username + ".txt"
    contentBytes, err := os.ReadFile(fname)
    if err != nil && !os.IsNotExist(err) {
        t.Fatalf("Error reading file: %v", err)
    }
    if err == nil && strings.Contains(string(contentBytes), "[?]") {
        t.Errorf("Expected no false positive because noFalsePositives flag is set, but found '[?]' in file")
    }
    DeleteOldFile(username)
}