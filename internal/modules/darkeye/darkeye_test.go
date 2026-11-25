package darkeye

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/ibnaleem/gosearch/internal/file"
)

const (
	testHIBRKey = "hibr-test-key"
	testBHKey   = "bh-test-key"
)

// sentRequest is what the fake servers saw of one request.
type sentRequest struct {
	product string
	uri     string
	auth    string
}

// fakeAPI stands in for both products on one server, so no test touches the
// live services. Each product has its own handler.
type fakeAPI struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []sentRequest

	hibr http.HandlerFunc
	bh   http.HandlerFunc
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()

	api := &fakeAPI{
		hibr: respond(http.StatusOK, `{"sources":[],"has_next":false}`),
		bh:   respond(http.StatusOK, emptyBreachHouse),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hibr/", func(w http.ResponseWriter, r *http.Request) {
		api.record("hibr", r)
		api.hibr(w, r)
	})
	mux.HandleFunc("/bh/", func(w http.ResponseWriter, r *http.Request) {
		api.record("bh", r)
		api.bh(w, r)
	})

	api.server = httptest.NewServer(mux)
	t.Cleanup(api.server.Close)

	return api
}

var colourCodes = regexp.MustCompile("\x1b\\[[0-9;]*m")

const emptyBreachHouse = `{"ransomware":[],"breaches":[],"leads":[],"stealers":[]}`

func (api *fakeAPI) record(product string, r *http.Request) {
	api.mu.Lock()
	defer api.mu.Unlock()

	api.requests = append(api.requests, sentRequest{product: product, uri: r.RequestURI, auth: r.Header.Get("Authorization")})
}

// sent returns the requests one product received, in order.
func (api *fakeAPI) sent(product string) []sentRequest {
	api.mu.Lock()
	defer api.mu.Unlock()

	var got []sentRequest
	for _, request := range api.requests {
		if request.product == product {
			got = append(got, request)
		}
	}

	return got
}

func respond(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// newTestClient builds the real client and points it at the fake API. It
// returns the client, what it printed and the directory its files go to.
func newTestClient(t *testing.T, api *fakeAPI, hibrKey, breachHouseKey string) (*darkEyeClient, *bytes.Buffer, string) {
	t.Helper()

	var out bytes.Buffer
	dir := t.TempDir()

	dec := NewDarkEyeClient(&out, file.NewFileWriter(dir), hibrKey, breachHouseKey).(*darkEyeClient)
	dec.hibrURL = api.server.URL + "/hibr/api/metadata"
	dec.breachHouseURL = api.server.URL + "/bh/api/v1/search"

	return dec, &out, dir
}

// savedOutput reads back what the module filed under the username.
func savedOutput(t *testing.T, dir string) string {
	t.Helper()

	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		t.Fatal(err)
	}

	var all strings.Builder
	for _, name := range files {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		all.Write(content)
	}

	return all.String()
}

func TestName(t *testing.T) {
	dec := NewDarkEyeClient(&bytes.Buffer{}, file.NewFileWriter(t.TempDir()), "", "")
	if got := dec.Name(); got != "DarkEye" {
		t.Errorf("Name() = %q, want DarkEye", got)
	}
}

func TestSearchRejectsEmptyQuery(t *testing.T) {
	api := newFakeAPI(t)
	dec, _, _ := newTestClient(t, api, testHIBRKey, testBHKey)

	if result, err := dec.Search(context.Background(), ""); err == nil || result != nil {
		t.Fatalf("Search(\"\") = %v, %v, want an error", result, err)
	}
}

func TestSearchWithoutKeysSkipsAndSendsNothing(t *testing.T) {
	api := newFakeAPI(t)
	dec, out, dir := newTestClient(t, api, "", "")

	result, err := dec.Search(context.Background(), "bob")
	if err != nil || result != nil {
		t.Fatalf("Search = %v, %v, want nil, nil", result, err)
	}

	if len(api.requests) != 0 {
		t.Errorf("sent %d request(s) with no key, want none", len(api.requests))
	}

	for _, want := range []string{
		"DARKEYE_HIBR_API_KEY not set, skipping HaveIBeenRansom.",
		"DARKEYE_BREACHHOUSE_API_KEY not set, skipping Breach House.",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	if strings.Contains(out.String(), "Searching") || strings.Contains(out.String(), "Generated") {
		t.Errorf("did work with no key:\n%s", out)
	}

	if saved := savedOutput(t, dir); saved != "" {
		t.Errorf("wrote a file with no key: %q", saved)
	}
}

func TestSearchOnlyHIBRKeyQueriesOnlyHIBR(t *testing.T) {
	api := newFakeAPI(t)
	dec, out, _ := newTestClient(t, api, testHIBRKey, "")

	if _, err := dec.Search(context.Background(), "bob"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := len(api.sent("bh")); got != 0 {
		t.Errorf("Breach House got %d request(s) without a key, want none", got)
	}

	if !strings.Contains(out.String(), "DARKEYE_BREACHHOUSE_API_KEY not set, skipping Breach House.") {
		t.Errorf("no Breach House skip line:\n%s", out)
	}

	if strings.Contains(out.String(), "DARKEYE_HIBR_API_KEY not set") {
		t.Errorf("HaveIBeenRansom reported as skipped despite its key:\n%s", out)
	}
}

func TestSearchOnlyBreachHouseKeyQueriesOnlyBreachHouse(t *testing.T) {
	api := newFakeAPI(t)
	dec, out, _ := newTestClient(t, api, "", testBHKey)

	if _, err := dec.Search(context.Background(), "bob"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := len(api.sent("hibr")); got != 0 {
		t.Errorf("HaveIBeenRansom got %d request(s) without a key, want none", got)
	}

	if got := len(api.sent("bh")); got != len(commonEmailDomains) {
		t.Errorf("Breach House got %d request(s), want %d", got, len(commonEmailDomains))
	}

	if !strings.Contains(out.String(), "DARKEYE_HIBR_API_KEY not set, skipping HaveIBeenRansom.") {
		t.Errorf("no HaveIBeenRansom skip line:\n%s", out)
	}
}

func TestSearchNeverSendsBareUsernameToBreachHouse(t *testing.T) {
	api := newFakeAPI(t)
	dec, _, _ := newTestClient(t, api, testHIBRKey, testBHKey)

	if _, err := dec.Search(context.Background(), "bob"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requests := api.sent("bh")
	if len(requests) != len(commonEmailDomains) {
		t.Fatalf("Breach House got %d request(s), want %d", len(requests), len(commonEmailDomains))
	}

	for _, request := range requests {
		if !strings.Contains(request.uri, "q=bob%40") {
			t.Errorf("Breach House request %q is not an email lookup", request.uri)
		}
	}
}

func TestSearchHyphenatedUsernameIsOnlyLookedUpByEmail(t *testing.T) {
	api := newFakeAPI(t)
	dec, out, _ := newTestClient(t, api, testHIBRKey, "")

	if _, err := dec.Search(context.Background(), "bob-smith"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requests := api.sent("hibr")
	if len(requests) != len(commonEmailDomains) {
		t.Fatalf("HaveIBeenRansom got %d request(s), want %d", len(requests), len(commonEmailDomains))
	}

	for _, request := range requests {
		if !strings.Contains(request.uri, "/email/bob-smith@") {
			t.Errorf("HaveIBeenRansom request %q is not an email lookup", request.uri)
		}
	}

	if !strings.Contains(out.String(), "only searched with its email addresses") {
		t.Errorf("no explanation for the skipped username lookup:\n%s", out)
	}
}

func TestSearchHyphenatedUsernameWithoutEmailsSendsNothing(t *testing.T) {
	api := newFakeAPI(t)
	dec, _, _ := newTestClient(t, api, testHIBRKey, "")

	result, err := dec.Search(context.Background(), "bob-smith@gmail.com")
	if err != nil || result != nil {
		t.Fatalf("Search = %v, %v, want nil, nil", result, err)
	}

	if len(api.requests) != 0 {
		t.Errorf("sent %d request(s), want none", len(api.requests))
	}
}

func TestSearchBreachHouseSkippedWhenUsernameCannotBeAnEmail(t *testing.T) {
	api := newFakeAPI(t)
	dec, out, _ := newTestClient(t, api, "", testBHKey)

	result, err := dec.Search(context.Background(), "bob@gmail.com")
	if err != nil || result != nil {
		t.Fatalf("Search = %v, %v, want nil, nil", result, err)
	}

	if len(api.requests) != 0 {
		t.Errorf("sent %d request(s), want none", len(api.requests))
	}

	if !strings.Contains(out.String(), "only searched with email addresses") {
		t.Errorf("no explanation for the skip:\n%s", out)
	}
}

func TestSearchRequestsAreBoundedAndAuthenticated(t *testing.T) {
	api := newFakeAPI(t)
	// every page claims another follows, so only the cap stops the run
	api.hibr = respond(http.StatusOK, `{"sources":[{"id_source":"x","post_title":"T"}],"has_next":true}`)
	dec, out, _ := newTestClient(t, api, testHIBRKey, testBHKey)

	if _, err := dec.Search(context.Background(), "bob"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 6 terms (username + 5 emails) x 2 pages
	hibr := api.sent("hibr")
	if want := 12; len(hibr) != want {
		t.Errorf("HaveIBeenRansom got %d request(s), want %d", len(hibr), want)
	}

	for _, request := range hibr {
		if request.auth != "Bearer "+testHIBRKey {
			t.Errorf("HaveIBeenRansom request %q sent Authorization %q", request.uri, request.auth)
		}

		if !strings.HasPrefix(request.uri, "/hibr/api/metadata/") {
			t.Errorf("unexpected HaveIBeenRansom path %q", request.uri)
		}

		if strings.Contains(request.uri, "fullstealer") {
			t.Errorf("called the full stealer endpoint: %q", request.uri)
		}
	}

	// one request per email
	bh := api.sent("bh")
	if want := 5; len(bh) != want {
		t.Fatalf("Breach House got %d request(s), want %d", len(bh), want)
	}

	for _, request := range bh {
		if request.auth != "Bearer "+testBHKey {
			t.Errorf("Breach House request %q sent Authorization %q", request.uri, request.auth)
		}
	}

	if !strings.Contains(out.String(), "has more records") {
		t.Errorf("no note that more records exist:\n%s", out)
	}
}

func TestSearchPrintsAndFilesRecordsWithProductAndCategory(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/username/bob") {
			respond(http.StatusOK, `{"sources":[
				{"id_source":"r-1","post_title":"Acme Corp","website":"acme.example","group_name":"lockers","country":"US","discovered":"2025-03-04T10:00:00Z","leak_type":"ransomware_leak","password":"hunter2"},
				{"id_source":"b-1","post_title":"Beta Inc","leak_type":"traditional_breach","hash":"5f4dcc3b5aa765d61d8327deb882cf99"}
			],"has_next":false}`)(w, r)
			return
		}

		respond(http.StatusOK, `{"sources":[],"has_next":false}`)(w, r)
	}
	api.bh = func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "q=bob%40gmail.com") {
			respond(http.StatusOK, `{"ransomware":[],"breaches":[],"leads":[],"stealers":[
				{"id":9,"post_title":"Stealer post for bob@gmail.com","website":"paste.example"},
				{"id":10,"post_title":"Some company","meta_description":"nothing relevant"}
			]}`)(w, r)
			return
		}

		respond(http.StatusOK, emptyBreachHouse)(w, r)
	}

	dec, out, dir := newTestClient(t, api, testHIBRKey, testBHKey)

	result, err := dec.Search(context.Background(), "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil || result.Module != "DarkEye" || result.Summary != "3 record(s) found" {
		t.Fatalf("result = %+v, want module DarkEye and 3 record(s) found", result)
	}

	saved := savedOutput(t, dir)

	for name, text := range map[string]string{"terminal": out.String(), "file": saved} {
		for _, want := range []string{
			"Product:  HaveIBeenRansom",
			"Category: ransomware",
			"Category: breach",
			"Product:  Breach House",
			"Category: stealer",
			"Acme Corp",
			"Stealer post for bob@gmail.com",
			"2025-03-04",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s output lacks %q:\n%s", name, want, text)
			}
		}

		for _, forbidden := range []string{"hunter2", "5f4dcc3b5aa765d61d8327deb882cf99", "Some company"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s output holds %q", name, forbidden)
			}
		}
	}
}

func TestSearchStripsTerminalControlsFromAPIText(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = respond(http.StatusOK, `{"sources":[{"id_source":"x","post_title":"\u001b[2JEVIL\u0007 corp","website":"a\u009bb"}],"has_next":false}`)
	dec, out, dir := newTestClient(t, api, testHIBRKey, "")

	if _, err := dec.Search(context.Background(), "bob"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// the colour codes of theme are the only escapes allowed in the output
	plain := colourCodes.ReplaceAllString(out.String(), "")
	for name, text := range map[string]string{"terminal": plain, "file": savedOutput(t, dir)} {
		if strings.ContainsAny(text, "\x1b\x07\u009b") {
			t.Errorf("%s output holds a control character:\n%q", name, text)
		}
	}
}

func TestSearchOneProductFailingKeepsTheOthersResults(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = respond(http.StatusOK, `{"sources":[{"id_source":"x","post_title":"Acme"}],"has_next":false}`)
	api.bh = respond(http.StatusInternalServerError, `{}`)
	dec, out, _ := newTestClient(t, api, testHIBRKey, testBHKey)

	result, err := dec.Search(context.Background(), "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil || !strings.Contains(result.Summary, "6 record(s) found") || !strings.Contains(result.Summary, "1 of 2 product(s) failed") {
		t.Fatalf("result = %+v, want 6 records and a failed product", result)
	}

	if !strings.Contains(out.String(), "Breach House lookup failed") {
		t.Errorf("failure not reported:\n%s", out)
	}
}

func TestSearchKeepsRecordsFromPagesReadBeforeAFailure(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/2") {
			respond(http.StatusInternalServerError, `{}`)(w, r)
			return
		}

		respond(http.StatusOK, `{"sources":[{"id_source":"x","post_title":"Acme"}],"has_next":true}`)(w, r)
	}
	dec, out, dir := newTestClient(t, api, testHIBRKey, "")

	result, err := dec.Search(context.Background(), "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil || !strings.Contains(result.Summary, "1 record(s) found, 1 of 1 product(s) failed") {
		t.Fatalf("result = %+v, want the first page's record and a failed product", result)
	}

	printed := colourCodes.ReplaceAllString(out.String(), "")
	for _, want := range []string{"HaveIBeenRansom lookup failed for bob", "Found 1 HaveIBeenRansom record(s) for bob", "failed partway, so these records are incomplete"} {
		if !strings.Contains(printed, want) {
			t.Errorf("output lacks %q:\n%s", want, printed)
		}
	}

	saved := savedOutput(t, dir)
	if !strings.Contains(saved, "Acme") || !strings.Contains(saved, "incomplete") {
		t.Errorf("partial records not filed as incomplete:\n%s", saved)
	}
}

func TestSearchFailureWithNoRecordsIsNotReportedAsNoMatch(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = respond(http.StatusOK, `{"sources":[],"has_next":false}`)
	api.bh = respond(http.StatusBadGateway, `{}`)
	dec, out, _ := newTestClient(t, api, testHIBRKey, testBHKey)

	result, err := dec.Search(context.Background(), "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil || !strings.Contains(result.Summary, "0 record(s) found, 1 of 2 product(s) failed") {
		t.Fatalf("result = %+v, want a partial summary", result)
	}

	if strings.Contains(out.String(), "No DarkEye records found") {
		t.Errorf("partial run reported as a clean no-match:\n%s", out)
	}
}

func TestSearchEveryProductFailingIsAnError(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = respond(http.StatusUnauthorized, `{}`)
	api.bh = respond(http.StatusServiceUnavailable, `{}`)
	dec, _, _ := newTestClient(t, api, testHIBRKey, testBHKey)

	result, err := dec.Search(context.Background(), "bob")
	if err == nil || result != nil {
		t.Fatalf("Search = %v, %v, want an error", result, err)
	}

	if !strings.HasPrefix(err.Error(), "DarkEye(Search): ") {
		t.Errorf("error %q is not wrapped with the module name", err)
	}
}

func TestSearchNothingFoundReturnsNil(t *testing.T) {
	api := newFakeAPI(t)
	dec, out, dir := newTestClient(t, api, testHIBRKey, testBHKey)

	result, err := dec.Search(context.Background(), "bob")
	if err != nil || result != nil {
		t.Fatalf("Search = %v, %v, want nil, nil", result, err)
	}

	if !strings.Contains(out.String(), "No DarkEye records found for bob.") {
		t.Errorf("no not-found line:\n%s", out)
	}

	if saved := savedOutput(t, dir); saved != "" {
		t.Errorf("wrote a file with nothing found: %q", saved)
	}
}

func TestSearchNon200IsAnErrorNotAnEmptyResult(t *testing.T) {
	statuses := []int{
		http.StatusNotFound,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
	}

	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			api := newFakeAPI(t)
			api.hibr = respond(status, `{"sources":[],"has_next":false}`)
			dec, _, _ := newTestClient(t, api, testHIBRKey, "")

			result, err := dec.Search(context.Background(), "bob")
			if err == nil || result != nil {
				t.Fatalf("status %d: Search = %v, %v, want an error", status, result, err)
			}
		})
	}
}

func TestSearchMalformedJSONIsAnError(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = respond(http.StatusOK, `<html>not json</html>`)
	dec, _, _ := newTestClient(t, api, testHIBRKey, "")

	if result, err := dec.Search(context.Background(), "bob"); err == nil || result != nil {
		t.Fatalf("Search = %v, %v, want an error", result, err)
	}
}

func TestSearchStopsAProductAtItsFirstFailure(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = respond(http.StatusUnauthorized, `{}`)
	dec, _, _ := newTestClient(t, api, testHIBRKey, "")

	if _, err := dec.Search(context.Background(), "bob"); err == nil {
		t.Fatal("want an error")
	}

	if got := len(api.sent("hibr")); got != 1 {
		t.Errorf("HaveIBeenRansom got %d request(s) after a 401, want 1", got)
	}
}

func TestSearchDoesNotFollowRedirects(t *testing.T) {
	var mu sync.Mutex
	var leaked []string

	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		leaked = append(leaked, r.Header.Get("Authorization"))
		respond(http.StatusOK, `{"sources":[],"has_next":false}`)(w, r)
	}))
	defer elsewhere.Close()

	api := newFakeAPI(t)
	api.hibr = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusFound)
	}
	dec, _, _ := newTestClient(t, api, testHIBRKey, "")

	result, err := dec.Search(context.Background(), "bob")
	if err == nil || result != nil {
		t.Fatalf("Search = %v, %v, want an error for a redirect", result, err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(leaked) != 0 {
		t.Errorf("followed a redirect to another host: %q", leaked)
	}
}

func TestSearchEscapesTheUsernameInThePath(t *testing.T) {
	api := newFakeAPI(t)
	dec, _, _ := newTestClient(t, api, testHIBRKey, "")

	if _, err := dec.Search(context.Background(), "a/b?c d"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requests := api.sent("hibr")
	if len(requests) != 1 {
		t.Fatalf("got %d request(s), want 1 (no emails can be built from a name with a space)", len(requests))
	}

	if want := "/hibr/api/metadata/username/a%2Fb%3Fc%20d"; requests[0].uri != want {
		t.Errorf("uri = %q, want %q", requests[0].uri, want)
	}
}

func TestSearchStopsOnCancelledContext(t *testing.T) {
	api := newFakeAPI(t)
	dec, _, _ := newTestClient(t, api, testHIBRKey, testBHKey)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := dec.Search(ctx, "bob")
	if err == nil || result != nil {
		t.Fatalf("Search = %v, %v, want an error", result, err)
	}

	if len(api.requests) != 0 {
		t.Errorf("sent %d request(s) on a cancelled context", len(api.requests))
	}
}
