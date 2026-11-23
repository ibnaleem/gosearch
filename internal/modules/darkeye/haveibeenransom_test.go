package darkeye

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func searchHIBR(t *testing.T, api *fakeAPI, field, term string) (lookup, error) {
	t.Helper()

	dec, _, _ := newTestClient(t, api, testHIBRKey, "")

	return dec.searchHaveIBeenRansom(context.Background(), probe{field: field, term: term})
}

func TestSearchHaveIBeenRansomCategories(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = respond(http.StatusOK, `{"sources":[
		{"id_source":"1","post_title":"A","leak_type":"ransomware_leak"},
		{"id_source":"2","post_title":"B","leak_type":"traditional_breach"},
		{"id_source":"3","post_title":"C","leak_type":"something_new"},
		{"id_source":"4","post_title":"D"}
	],"has_next":false}`)

	found, err := searchHIBR(t, api, "username", "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for _, rec := range found.records {
		got = append(got, rec.Product+"/"+rec.Category)
	}

	want := "HaveIBeenRansom/ransomware HaveIBeenRansom/breach HaveIBeenRansom/leak HaveIBeenRansom/leak"
	if strings.Join(got, " ") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}

func TestSearchHaveIBeenRansomReadsNextPageThenStops(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/2") {
			respond(http.StatusOK, `{"sources":[{"id_source":"2","post_title":"Second"}],"has_next":false}`)(w, r)
			return
		}

		respond(http.StatusOK, `{"sources":[{"id_source":"1","post_title":"First"}],"has_next":true}`)(w, r)
	}

	found, err := searchHIBR(t, api, "email", "bob@gmail.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(found.records) != 2 || found.truncated {
		t.Errorf("got %d record(s), truncated=%v, want 2 and not truncated", len(found.records), found.truncated)
	}

	requests := api.sent("hibr")
	if len(requests) != 2 ||
		requests[0].uri != "/hibr/api/metadata/email/bob@gmail.com" ||
		requests[1].uri != "/hibr/api/metadata/email/bob@gmail.com/2" {
		t.Errorf("requests = %+v, want page 1 then /2", requests)
	}
}

func TestSearchHaveIBeenRansomMarksTruncationAtThePageCap(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = respond(http.StatusOK, `{"sources":[{"id_source":"1","post_title":"X"}],"has_next":true}`)

	found, err := searchHIBR(t, api, "username", "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !found.truncated {
		t.Error("not marked truncated although a next page was left unread")
	}

	if got := len(api.sent("hibr")); got != maxHIBRPages {
		t.Errorf("read %d page(s), want %d", got, maxHIBRPages)
	}

	if len(found.records) != 1 {
		t.Errorf("got %d record(s), want the repeated listing once", len(found.records))
	}
}

func TestSearchHaveIBeenRansomAcceptsResultsAndPagination(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = respond(http.StatusOK, `{"results":[{"id":5,"name":"Gamma"}],"pagination":{"has_next":false}}`)

	found, err := searchHIBR(t, api, "username", "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(found.records) != 1 || found.records[0].ID != "5" || found.records[0].Title != "Gamma" {
		t.Errorf("records = %+v, want Gamma with id 5", found.records)
	}
}

func TestSearchHaveIBeenRansomEmptyListIsNoRecords(t *testing.T) {
	api := newFakeAPI(t)

	found, err := searchHIBR(t, api, "username", "bob")
	if err != nil || len(found.records) != 0 {
		t.Fatalf("got %+v, %v, want no records and no error", found, err)
	}
}

func TestSearchHaveIBeenRansomRejectsBadShapes(t *testing.T) {
	tests := map[string]string{
		"no listing key":        `{"has_next":false}`,
		"no has_next":           `{"sources":[]}`,
		"has_next not a bool":   `{"sources":[],"has_next":"no"}`,
		"sources not a list":    `{"sources":{"a":1},"has_next":false}`,
		"item not an object":    `{"sources":["x"],"has_next":false}`,
		"success false":         `{"success":false,"sources":[],"has_next":false}`,
		"error key":             `{"error":"nope","sources":[],"has_next":false}`,
		"listing without a key": `{"sources":[{"country":"US"}],"has_next":false}`,
		"not an object":         `[]`,
		"not json":              `nope`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI(t)
			api.hibr = respond(http.StatusOK, body)

			if _, err := searchHIBR(t, api, "username", "bob"); err == nil {
				t.Errorf("body %s accepted, want an error", body)
			}
		})
	}
}

func TestSearchHaveIBeenRansomKeepsEarlierPageWhenALaterOneFails(t *testing.T) {
	api := newFakeAPI(t)
	api.hibr = func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/2") {
			respond(http.StatusInternalServerError, `{}`)(w, r)
			return
		}

		respond(http.StatusOK, `{"sources":[{"id_source":"1","post_title":"First"}],"has_next":true}`)(w, r)
	}

	found, err := searchHIBR(t, api, "username", "bob")
	if err == nil {
		t.Fatal("want an error from the failed page")
	}

	if len(found.records) != 1 {
		t.Errorf("got %d record(s), want the first page kept", len(found.records))
	}
}
