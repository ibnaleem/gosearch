package darkeye

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestMentions(t *testing.T) {
	const email = "bob@gmail.com"

	tests := []struct {
		name  string
		field string
		want  bool
	}{
		{"whole field", "bob@gmail.com", true},
		{"upper case", "BOB@GMAIL.COM", true},
		{"inside a sentence", "contact bob@gmail.com for details", true},
		{"followed by a full stop", "write to bob@gmail.com.", true},
		{"in angle brackets", "<bob@gmail.com>", true},
		{"after a colon", "email:bob@gmail.com", true},
		{"longer local part before", "rob.bob@gmail.com", false},
		{"word character before", "xbob@gmail.com", false},
		{"plus tag before", "a+bob@gmail.com", false},
		{"other address before", "x@bob@gmail.com", false},
		{"longer domain after", "bob@gmail.com.au", false},
		{"longer domain label after", "bob@gmail.community", false},
		{"hyphen after", "bob@gmail.com-x", false},
		{"other address after", "bob@gmail.com@x", false},
		{"different address", "bobby@gmail.com", false},
		{"only the domain", "gmail.com", false},
		{"second occurrence stands alone", "xbob@gmail.com and bob@gmail.com", true},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mentions(email, tt.field); got != tt.want {
				t.Errorf("mentions(%q, %q) = %v, want %v", email, tt.field, got, tt.want)
			}
		})
	}
}

func TestMentionsChecksEveryField(t *testing.T) {
	if !mentions("bob@gmail.com", "nothing", "", "see bob@gmail.com") {
		t.Error("an address in a later field was missed")
	}
}

func searchBH(t *testing.T, api *fakeAPI, email string) (lookup, error) {
	t.Helper()

	dec, _, _ := newTestClient(t, api, "", testBHKey)

	return dec.searchBreachHouse(context.Background(), probe{field: "email", term: email})
}

func TestSearchBreachHouseRequestShape(t *testing.T) {
	api := newFakeAPI(t)

	if _, err := searchBH(t, api, "bob+x@gmail.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requests := api.sent("bh")
	if len(requests) != 1 {
		t.Fatalf("got %d request(s), want 1", len(requests))
	}

	if want := "/bh/api/v1/search?q=bob%2Bx%40gmail.com&limit=25"; requests[0].uri != want {
		t.Errorf("uri = %q, want %q", requests[0].uri, want)
	}
}

func TestSearchBreachHouseKeepsOnlyExactAddressMatches(t *testing.T) {
	api := newFakeAPI(t)
	api.bh = respond(http.StatusOK, `{
		"ransomware":[
			{"id":1,"post_title":"Victim named bob","website":"victim.example"},
			{"id":2,"name":"Bob@Gmail.com"}
		],
		"breaches":{"total":2,"results":[
			{"id":3,"post_title":"Dump","meta_description":"includes xbob@gmail.com"},
			{"id":4,"post_title":"Dump 2","meta_description":"includes bob@gmail.com in the sample"}
		]},
		"leads":[{"id":5,"website":"bob@gmail.com"}],
		"stealers":[{"id":6,"post_title":"bob@gmail.com.au"}]
	}`)

	found, err := searchBH(t, api, "bob@gmail.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for _, rec := range found.records {
		got = append(got, rec.Category+":"+rec.ID)
	}

	if want := "ransomware:2 breach:4 leads:5"; strings.Join(got, " ") != want {
		t.Errorf("kept %v, want %s", got, want)
	}

	if found.truncated {
		t.Error("marked truncated although every total matches what came back")
	}
}

func TestSearchBreachHouseMarksTruncation(t *testing.T) {
	tests := map[string]string{
		"total above the results": `{"ransomware":{"total":50,"results":[]},"breaches":[],"leads":[],"stealers":[]}`,
		"a full unlabelled list":  `{"ransomware":[],"breaches":[` + strings.TrimSuffix(strings.Repeat(`{"id":1,"name":"x"},`, breachHouseLimit), ",") + `],"leads":[],"stealers":[]}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI(t)
			api.bh = respond(http.StatusOK, body)

			found, err := searchBH(t, api, "bob@gmail.com")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !found.truncated {
				t.Error("not marked truncated")
			}
		})
	}
}

func TestSearchBreachHouseRejectsBadShapes(t *testing.T) {
	tests := map[string]string{
		"missing section":     `{"ransomware":[],"breaches":[],"leads":[]}`,
		"null section":        `{"ransomware":null,"breaches":[],"leads":[],"stealers":[]}`,
		"section is a string": `{"ransomware":"x","breaches":[],"leads":[],"stealers":[]}`,
		"object without list": `{"ransomware":{"total":1},"breaches":[],"leads":[],"stealers":[]}`,
		"item not an object":  `{"ransomware":["x"],"breaches":[],"leads":[],"stealers":[]}`,
		"success false":       `{"success":false,"ransomware":[],"breaches":[],"leads":[],"stealers":[]}`,
		"error key":           `{"error":"no","ransomware":[],"breaches":[],"leads":[],"stealers":[]}`,
		"not an object":       `[]`,
		"not json":            `nope`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI(t)
			api.bh = respond(http.StatusOK, body)

			if _, err := searchBH(t, api, "bob@gmail.com"); err == nil {
				t.Errorf("body %s accepted, want an error", body)
			}
		})
	}
}

func TestSearchBreachHouseNon200IsAnError(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusInternalServerError} {
		api := newFakeAPI(t)
		api.bh = respond(status, emptyBreachHouse)

		if _, err := searchBH(t, api, "bob@gmail.com"); err == nil {
			t.Errorf("status %d accepted, want an error", status)
		}
	}
}
