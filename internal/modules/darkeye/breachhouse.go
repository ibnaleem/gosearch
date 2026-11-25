package darkeye

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ibnaleem/gosearch/internal/modules"
)

// breachHouseLimit is how many results Breach House is asked for per source.
// One request per email, so a run sends at most 5.
const breachHouseLimit = 25

// breachHouseResponse is the search shape: one section per source. Each is a
// bare list or an object with a "total" and the list under "results".
type breachHouseResponse struct {
	Success    *bool           `json:"success"`
	Error      json.RawMessage `json:"error"`
	Ransomware json.RawMessage `json:"ransomware"`
	Breaches   json.RawMessage `json:"breaches"`
	Leads      json.RawMessage `json:"leads"`
	Stealers   json.RawMessage `json:"stealers"`
}

// breachHouseSource is one section of the response, with the category its
// records are printed under.
type breachHouseSource struct {
	category string
	raw      json.RawMessage
}

type breachHouseSection struct {
	Total   int        `json:"total"`
	Results *[]listing `json:"results"`
}

// searchBreachHouse looks an email up. The search is free text over victim and
// listing fields, so a record is kept only when the exact address appears in
// its post_title, name, website or meta_description. Anything else is a
// listing that merely resembles the query, and is dropped.
func (dec *darkEyeClient) searchBreachHouse(ctx context.Context, p probe) (lookup, error) {
	var found lookup

	endpoint := fmt.Sprintf("%s?q=%s&limit=%d", dec.breachHouseURL, url.QueryEscape(p.term), breachHouseLimit)

	response, err := modules.FetchJSON[breachHouseResponse](ctx, dec.httpClient, endpoint, bearer(dec.breachHouseKey))
	if err != nil {
		return found, fmt.Errorf("%s(searchBreachHouse): %w", dec.Name(), err)
	}

	if response.Success != nil && !*response.Success {
		return found, fmt.Errorf("%s(searchBreachHouse): response reports failure", dec.Name())
	}

	if holdsError(response.Error) {
		return found, fmt.Errorf("%s(searchBreachHouse): response holds an error", dec.Name())
	}

	sections := []breachHouseSource{
		{"ransomware", response.Ransomware},
		{"breach", response.Breaches},
		{"leads", response.Leads},
		{"stealer", response.Stealers},
	}

	seen := make(map[string]bool)

	for _, section := range sections {
		items, total, err := section.items()
		if err != nil {
			return found, fmt.Errorf("%s(searchBreachHouse): %s: %w", dec.Name(), section.category, err)
		}

		// more results exist than were returned, so a match could be missing
		if total > len(items) || (total == 0 && len(items) >= breachHouseLimit) {
			found.truncated = true
		}

		for _, item := range items {
			if !mentions(p.term, string(item.PostTitle), string(item.Name), string(item.Website), string(item.MetaDescription)) {
				continue
			}

			rec := newRecord(breachHouse, section.category, item)

			key := section.category + "\x00" + rec.ID
			if rec.ID == "" {
				key = section.category + "\x00" + rec.Title + "\x00" + rec.Website + "\x00" + rec.Date
			}

			if seen[key] {
				continue
			}

			seen[key] = true
			found.records = append(found.records, rec)
		}
	}

	return found, nil
}

// items decodes the section into its listings and the total the API says
// matched (0 when it doesn't say). A missing or oddly shaped section is an
// error, not an empty one.
func (bhs breachHouseSource) items() ([]listing, int, error) {
	var items []listing
	if err := json.Unmarshal(bhs.raw, &items); err == nil && items != nil {
		return items, 0, nil
	}

	var section breachHouseSection
	if err := json.Unmarshal(bhs.raw, &section); err != nil || section.Results == nil {
		return nil, 0, errors.New("unexpected section shape")
	}

	return *section.Results, section.Total, nil
}

// mentions reports whether the exact email address appears, ignoring case, in
// any of the fields. The address has to stand alone: "bob@gmail.com" is not in
// "rob.bob@gmail.com" or "bob@gmail.com.au", which are other addresses.
func mentions(email string, fields ...string) bool {
	needle := strings.ToLower(email)

	for _, field := range fields {
		if containsAddress(strings.ToLower(strings.ToValidUTF8(field, "")), needle) {
			return true
		}
	}

	return false
}

func containsAddress(haystack, address string) bool {
	if address == "" {
		return false
	}

	for start := 0; start < len(haystack); {
		index := strings.Index(haystack[start:], address)
		if index < 0 {
			return false
		}

		index += start
		end := index + len(address)

		if addressStartsAt(haystack[:index]) && addressEndsAt(haystack[end:]) {
			return true
		}

		_, size := utf8.DecodeRuneInString(haystack[index:])
		start = index + size
	}

	return false
}

// localPartRunes are the symbols an unquoted local part can hold (RFC 5322
// atext and "."), plus "@". One of them before a match means it is the tail of
// a longer address: "bob@gmail.com" is not in "o'bob@gmail.com". "/" and "="
// are left out, because they usually end a URL path or query key, not an
// address.
const localPartRunes = ".@!#$%&'*+-?^`{|}~"

// addressStartsAt reports whether the text before a match leaves it standing
// alone, rather than being the tail of a longer local part.
func addressStartsAt(before string) bool {
	last, _ := utf8.DecodeLastRuneInString(before)
	if before == "" {
		return true
	}

	return !isWordRune(last) && !strings.ContainsRune(localPartRunes, last)
}

// addressEndsAt is the same check for the text after a match: it must not run
// on into a longer domain ("gmail.com.au") or another address part.
func addressEndsAt(after string) bool {
	if after == "" {
		return true
	}

	first, size := utf8.DecodeRuneInString(after)
	if isWordRune(first) || strings.ContainsRune("@+-", first) {
		return false
	}

	if first == '.' {
		next, _ := utf8.DecodeRuneInString(after[size:])
		return !isWordRune(next)
	}

	return true
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}
