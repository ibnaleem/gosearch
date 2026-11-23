package darkeye

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/ibnaleem/gosearch/internal/modules"
)

// maxHIBRPages is how many 20-record pages are read per term. It bounds the
// requests of a run: 6 terms (the username and 5 emails) x 2 pages = 12.
const maxHIBRPages = 2

// hibrResponse is the metadata search shape: one page of listings and whether
// another page follows. The listings are under "sources" (or "results") and
// the flag is top level or under "pagination". Pointers tell a missing field
// from an empty one, because a response without them is not an answer.
type hibrResponse struct {
	Success    *bool           `json:"success"`
	Error      json.RawMessage `json:"error"`
	Sources    *[]listing      `json:"sources"`
	Results    *[]listing      `json:"results"`
	HasNext    *bool           `json:"has_next"`
	Pagination *struct {
		HasNext *bool `json:"has_next"`
	} `json:"pagination"`
}

// hibrCategories maps HaveIBeenRansom's leak_type to the category printed.
// Anything else is a plain "leak".
var hibrCategories = map[string]string{
	"ransomware_leak":    "ransomware",
	"traditional_breach": "breach",
}

// searchHaveIBeenRansom reads the listing metadata for one term. It never
// calls the full stealer endpoint: that one returns clear-text credentials,
// and only listing metadata is printed or saved.
func (dec *darkEyeClient) searchHaveIBeenRansom(ctx context.Context, p probe) (lookup, error) {
	var found lookup

	base := dec.hibrURL + "/" + p.field + "/" + url.PathEscape(p.term)
	seen := make(map[string]bool)

	for page := 1; page <= maxHIBRPages; page++ {
		endpoint := base
		if page > 1 {
			endpoint = fmt.Sprintf("%s/%d", base, page)
		}

		response, err := modules.FetchJSON[hibrResponse](ctx, dec.httpClient, endpoint, bearer(dec.hibrKey))
		if err != nil {
			return found, fmt.Errorf("%s(searchHaveIBeenRansom): %w", dec.Name(), err)
		}

		items, hasNext, err := response.page()
		if err != nil {
			return found, fmt.Errorf("%s(searchHaveIBeenRansom): %w", dec.Name(), err)
		}

		for _, item := range items {
			category := hibrCategories[clean(string(item.LeakType))]
			if category == "" {
				category = "leak"
			}

			rec := newRecord(haveIBeenRansom, category, item)
			if rec.ID == "" && rec.Title == "" && rec.Website == "" {
				return found, fmt.Errorf("%s(searchHaveIBeenRansom): listing without an id, title or website", dec.Name())
			}

			// the same listing can come back on two pages
			key := rec.ID
			if key == "" {
				key = rec.Title + "\x00" + rec.Website + "\x00" + rec.Date
			}

			if seen[key] {
				continue
			}

			seen[key] = true
			found.records = append(found.records, rec)
		}

		if !hasNext {
			return found, nil
		}
	}

	found.truncated = true

	return found, nil
}

// page checks the response shape and returns its listings and has_next.
func (hr *hibrResponse) page() ([]listing, bool, error) {
	if hr.Success != nil && !*hr.Success {
		return nil, false, errors.New("response reports failure")
	}

	if len(hr.Error) > 0 {
		return nil, false, errors.New("response holds an error")
	}

	items := hr.Sources
	if items == nil {
		items = hr.Results
	}

	hasNext := hr.HasNext
	if hasNext == nil && hr.Pagination != nil {
		hasNext = hr.Pagination.HasNext
	}

	if items == nil || hasNext == nil {
		return nil, false, errors.New("unexpected response shape")
	}

	return *items, *hasNext, nil
}
