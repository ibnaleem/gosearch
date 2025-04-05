package main

import (
    "sync"
    "testing"
    "os"
    "net/http"
    "net/http/httptest"
"strings"
    "bytes"
    "io"
)
    
// fakeRoundTripper is a custom RoundTripper for testing the CrackHash function.
type fakeRoundTripper struct{}
func (rt fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
    if req.URL.Host == "weakpass.com" {
        responseBody := `{"type": "dummy", "hash": "dummyhash", "pass": "secret"}`
        return &http.Response{
            StatusCode:    200,
            Body:          io.NopCloser(bytes.NewBufferString(responseBody)),
            Header:        make(http.Header),
            ContentLength: int64(len(responseBody)),
        }, nil
    }
    return http.DefaultTransport.RoundTrip(req)
}
// fakeProxyNovaTransport is a package-level fake transport for simulating ProxyNova responses in tests.
type fakeProxyNovaTransport struct{}
func (f fakeProxyNovaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    if req.URL.Host == "api.proxynova.com" {
        responseBody := `{"count": 1, "lines": ["email@example.com:password123"]}`
        return &http.Response{
            StatusCode:    200,
            Body:          io.NopCloser(bytes.NewBufferString(responseBody)),
            Header:        make(http.Header),
            ContentLength: int64(len(responseBody)),
        }, nil
    }
    return http.DefaultTransport.RoundTrip(req)
}
// TestBuildDomains tests that BuildDomains correctly creates a list of domains using the given username.
func TestBuildDomains(t *testing.T) {
    username := "john"
    domains := BuildDomains(username)
    expectedDomainCount := 26 // there are 26 TLDs in the list from gosearch.go
    if len(domains) != expectedDomainCount {
        t.Errorf("BuildDomains() failed: expected %d domains, got %d", expectedDomainCount, len(domains))
    }
    // verify the first generated domain is "john.com"
    if len(domains) > 0 && domains[0] != username+".com" {
        t.Errorf("BuildDomains first element failed: expected %s, got %s", username+".com", domains[0])
    }
}
func TestDeleteOldFile(t *testing.T) {
    username := "testuser"
    filename := username + ".txt"
    // create the file with dummy content
    err := os.WriteFile(filename, []byte("dummy data"), 0644)
    if err != nil {
        t.Fatalf("Error creating file %s: %v", filename, err)
    }
    // verify that file exists
    if _, err := os.Stat(filename); os.IsNotExist(err) {
        t.Fatalf("File %s should exist before deletion", filename)
    }
    // call DeleteOldFile to remove the file
    DeleteOldFile(username)
    // verify that file no longer exists
    if _, err := os.Stat(filename); !os.IsNotExist(err) {
        t.Errorf("Expected file %s to be deleted, but it still exists", filename)
    }
}
// TestMakeRequestWithProfilePresence tests that MakeRequestWithProfilePresence correctly detects an existing profile based on the error message in the response.
func TestMakeRequestWithProfilePresence(t *testing.T) {
    // Create a fake HTTP server that returns a body with the trigger string "profile exists"
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("This is a test response with profile exists"))
    }))
    defer server.Close()

    // Reset the global count for test isolation.
    count.Store(0)

    username := "testuser"
    website := Website{
        Name:            "TestSite",
        BaseURL:         server.URL + "/{}",
        FollowRedirects: true,
        ErrorMsg:        "profile exists", // the trigger string expected to be found in the response
    }

    // Build the URL with the given username.
    url := BuildURL(website.BaseURL, username)

    // Invoke the function under test.
    MakeRequestWithProfilePresence(website, url, username)

    // Verify that the global count was incremented (meaning the profile was considered present).
    if count.Load() != 1 {
        t.Errorf("Expected count to be 1 after profile presence found, got %d", count.Load())
    }

    // Verify that the file was written.
    filename := username + ".txt"
    _, err := os.ReadFile(filename)
    if err != nil {
        t.Errorf("Expected file %s to be created, but got error: %v", filename, err)
    }

    // Cleanup the created file.
    os.Remove(filename)
}
// TestMakeRequestWithErrorMsg tests that MakeRequestWithErrorMsg correctly detects an existing profile by checking that the error message is absent from the response.
func TestMakeRequestWithErrorMsg(t *testing.T) {
    // Create an httptest server that returns a response without the error trigger ("user not found"),
    // which simulates that the profile exists.
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Profile data exists for this user"))
    }))
    defer server.Close()

    // Reset the global count and ensure the file does not exist before the test.
    count.Store(0)
    username := "testuser2"
    filename := username + ".txt"
    os.Remove(filename)

    // Set up a website that uses MakeRequestWithErrorMsg.
    // The ErrorMsg "user not found" would indicate a non-existing profile.
    // Since the response from our server does not contain this text, the profile is considered to exist.
    website := Website{
        Name:            "TestSiteErrorMsg",
        BaseURL:         server.URL + "/{}",
        FollowRedirects: true,
        ErrorMsg:        "user not found",
    }

    // Build the URL for the given username.
    url := BuildURL(website.BaseURL, username)

    // Invoke the function under test.
    MakeRequestWithErrorMsg(website, url, username)

    // Check that the global count was incremented indicating a detected profile.
    if count.Load() != 1 {
        t.Errorf("Expected count to be 1 after profile exists detection, got %d", count.Load())
    }

    // Verify that the expected file was written with the URL.
    data, err := os.ReadFile(filename)
    if err != nil {
        t.Errorf("Expected file %s to be created, got error: %v", filename, err)
    }
    if !strings.Contains(string(data), username) {
        t.Errorf("File content does not contain expected username")
    }

    // Cleanup: remove the created file.
    os.Remove(filename)
}
// TestMakeRequestWithResponseURL verifies that MakeRequestWithResponseURL correctly
// detects when the response URL differs from the expected URL and then writes the output
// and increments the global count.
func TestMakeRequestWithResponseURL(t *testing.T) {
    // Setup an httptest server that responds normally.
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Test response without redirection"))
    }))
    defer server.Close()

    // Reset count and remove any file that may exist from previous tests.
    count.Store(0)
    username := "responseuser"
    filename := username + ".txt"
    os.Remove(filename)

    // Setup a Website struct with a ResponseURL that (when formatted) differs from the
    // actual request URL.
    website := Website{
        Name:            "TestResponseURL",
        BaseURL:         server.URL + "/{}",
        ResponseURL:     "http://example.com/{}",
        FollowRedirects: true,
    }

    // Build the URL from the BaseURL.
    url := BuildURL(website.BaseURL, username)

    // Invoke the function under test.
    MakeRequestWithResponseURL(website, url, username)

    // Now, since the response URL (server.URL replacement) does not match the formatted
    // website.ResponseURL, the function should have written the profile URL and incremented count.
    if count.Load() != 1 {
        t.Errorf("Expected count to be 1, got %d", count.Load())
    }

    // Verify that the file was written with the expected URL.
    data, err := os.ReadFile(filename)
    if err != nil {
        t.Errorf("Expected file %s to be created, but got error: %v", filename, err)
    }

    expectedContent := BuildURL(website.BaseURL, username) + "\n"
    if !strings.Contains(string(data), expectedContent) {
        t.Errorf("Expected file content to contain %q, got %q", expectedContent, string(data))
    }

    // Cleanup the file.
    os.Remove(filename)
    }
// TestMakeRequestWithErrorCode tests that MakeRequestWithErrorCode correctly writes the profile URL
func TestMakeRequestWithErrorCode(t *testing.T) {
    // Create an httptest server that returns a status 200 OK,
    // while we set the expected ErrorCode to 404.
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK) // returns 200
        w.Write([]byte("Test response for error code"))
    }))
    defer server.Close()

    // Reset the global count and remove file from previous test runs.
    count.Store(0)
    username := "errorcodeuser"
    filename := username + ".txt"
    os.Remove(filename)

    website := Website{
        Name:            "TestErrorCode",
        BaseURL:         server.URL + "/{}",
        FollowRedirects: true,
        ErrorCode:       404, // Expected ErrorCode differs from server's 200 response.
    }

    // Build the URL using the website data.
    testURL := BuildURL(website.BaseURL, username)
    MakeRequestWithErrorCode(website, testURL, username)

    // Ensure that the global count is incremented, implying detection.
    if count.Load() != 1 {
        t.Errorf("Expected count to be 1 after detection, got %d", count.Load())
    }

    // Verify that the file was written with the expected URL.
    data, err := os.ReadFile(filename)
    if err != nil {
        t.Errorf("Expected file %s to be created, but got error: %v", filename, err)
    }
    expectedContent := BuildURL(website.BaseURL, username) + "\n"
    if !strings.Contains(string(data), expectedContent) {
        t.Errorf("Expected file content to contain %q, got %q", expectedContent, string(data))
    }

    // Cleanup the created file.
    os.Remove(filename)
}
// TestSearchFunction tests that the Search function correctly detects profiles via different error types
// and writes the corresponding URLs into the output file.
func TestSearchFunction(t *testing.T) {
    // Create a fake HTTP server that returns HTTP 200 with a response body
    // that does not contain the trigger text for non-existing profiles.
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Profile exists"))
    }))
    defer server.Close()

    // Reset the global count and remove any pre-existing file.
    count.Store(0)
    username := "testsearch"
    filename := username + ".txt"
    os.Remove(filename)

    // Create a test Data struct with two websites:
    // - One using errorMsg: the response will not contain "user not found", so it should detect the profile.
    // - One using status_code: the server response (200) does not match the expected 404, so it should detect the profile.
    data := Data{
        Websites: []Website{
            {
                Name:            "ErrorMsgSite",
                BaseURL:         server.URL + "/{}",
                FollowRedirects: true,
                ErrorMsg:        "user not found",
                ErrorType:       "errorMsg",
            },
            {
                Name:            "ErrorCodeSite",
                BaseURL:         server.URL + "/{}",
                FollowRedirects: true,
                ErrorCode:       404,
                ErrorType:       "status_code",
            },
        },
    }

    // Create a WaitGroup and add count equal to number of websites.
    var wg sync.WaitGroup
    wg.Add(len(data.Websites))

    // Call the Search function, which launches a goroutine for each website.
    Search(data, username, false, &wg)
    wg.Wait()

    // Verify that the global count increased by 2 (both websites detected a profile).
    if count.Load() != 2 {
        t.Errorf("Expected count to be 2, got %d", count.Load())
    }

    // Verify that the file contains the expected URL for both websites.
    content, err := os.ReadFile(filename)
    if err != nil {
        t.Fatalf("Expected file %s to be created, but got error: %v", filename, err)
    }
    expectedURL := BuildURL(data.Websites[0].BaseURL, username) + "\n"
    occurrences := strings.Count(string(content), expectedURL)
    if occurrences != 2 {
        t.Errorf("Expected URL %q to appear 2 times in file, got %d times", expectedURL, occurrences)
    }

    // Cleanup the file.
    os.Remove(filename)
    }
// TestSearchUnknownErrorType tests the Search function with an unknown ErrorType,
func TestSearchUnknownErrorType(t *testing.T) {
    // TestSearchUnknownErrorType tests the Search function when provided with a website that has an unknown ErrorType.
    // Reset the global count and remove any pre-existing output file.
    count.Store(0)
    username := "unknownuser"
    filename := username + ".txt"
    os.Remove(filename)

    // Create test data with a website having an unknown ErrorType.
    data := Data{
        Websites: []Website{
            {
                Name:            "UnknownSite",
                BaseURL:         "http://example.com/{}",
                ErrorType:       "unknown",
                FollowRedirects: true,
            },
        },
    }

    // Create a WaitGroup for the Search function.
    var wg sync.WaitGroup
    wg.Add(len(data.Websites))

    // Call Search with noFalsePositives set to false, so that it writes false positives.
    Search(data, username, false, &wg)
    wg.Wait()

    // Verify that the global count was incremented.
    if count.Load() != 1 {
        t.Errorf("Expected count to be 1, got %d", count.Load())
    }

    // Verify that the file was written with the expected URL.
    content, err := os.ReadFile(filename)
    if err != nil {
        t.Fatalf("Expected file %s to be created: %v", filename, err)
    }

    expected := "[?] " + BuildURL("http://example.com/{}", username) + "\n"
    if !strings.Contains(string(content), expected) {
        t.Errorf("Expected file content to contain %q, got %q", expected, string(content))
    }

    // Cleanup the output file.
    os.Remove(filename)
}
// TestCrackHash tests the CrackHash function by replacing the default transport 
// with fakeRoundTripper so that an HTTP call to weakpass.com returns a canned response.
func TestCrackHash(t *testing.T) {
    // Save the original transport and restore after the test.
    originalTransport := http.DefaultTransport
    defer func() { http.DefaultTransport = originalTransport }()
    http.DefaultTransport = fakeRoundTripper{}

    // Call CrackHash with a dummy hash that our fakeRoundTripper recognizes.
    pass := CrackHash("dummyhash")
    if pass != "secret" {
        t.Errorf("CrackHash failed: expected 'secret', got '%s'", pass)
    }
}
// TestSearchProxyNova tests the SearchProxyNova function using a fake HTTP transport to simulate a response with compromised password data.
func TestSearchProxyNova(t *testing.T) {
    // Save the original HTTP transport and restore after the test
    originalTransport := http.DefaultTransport
    defer func() { http.DefaultTransport = originalTransport }()

    // Define a fake transport that intercepts requests to api.proxynova.com
    http.DefaultTransport = fakeProxyNovaTransport{}

    // Prepare environment: reset file (if exists) for test user and clear any previous output.
    username := "testproxyuser"
    filename := username + ".txt"
    os.Remove(filename)

    // Use a WaitGroup to wait for the SearchProxyNova function to finish
    var wg sync.WaitGroup
    wg.Add(1)
    SearchProxyNova(username, &wg)
    wg.Wait()

    // Verify that the file was created and contains the compromised password details
    data, err := os.ReadFile(filename)
    if err != nil {
        t.Fatalf("Expected file %s to be created, but got error: %v", filename, err)
    }
    if !strings.Contains(string(data), "email@example.com") || !strings.Contains(string(data), "password123") {
        t.Errorf("File content does not contain expected compromised password details. Got: %s", string(data))
    }

    // Cleanup the created file after test
    os.Remove(filename)
}