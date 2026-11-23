package darkeye

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ibnaleem/gosearch/internal/theme"
)

// maxTextRunes caps one API text field, so a hostile or broken response can't
// flood the terminal or the output file.
const maxTextRunes = 256

// text is a JSON value read as printable text. A string or a number is kept
// and anything else (null, bool, object, array) becomes empty, so one odd
// field doesn't fail a whole response.
type text string

func (t *text) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	switch typed := value.(type) {
	case string:
		*t = text(typed)
	case float64:
		*t = text(strings.TrimSpace(string(data)))
	default:
		*t = ""
	}

	return nil
}

// record is the listing metadata of one hit. It holds no credentials or leaked
// content: only where the hit came from and what the listing says.
type record struct {
	Product  string
	Category string
	ID       string
	Title    string
	Website  string
	Group    string
	Country  string
	Date     string
}

// listing is one item of a HaveIBeenRansom or Breach House response. Only the
// listing metadata is declared, so nothing else in the response is ever read.
type listing struct {
	IDSource        text `json:"id_source"`
	VictimID        text `json:"victim_id"`
	ID              text `json:"id"`
	PostTitle       text `json:"post_title"`
	Name            text `json:"name"`
	Website         text `json:"website"`
	GroupName       text `json:"group_name"`
	Country         text `json:"country"`
	Discovered      text `json:"discovered"`
	LeakType        text `json:"leak_type"`
	MetaDescription text `json:"meta_description"`
}

// newRecord turns a listing into a printable record. The first non-empty of
// the alternative id and title fields wins.
func newRecord(product, category string, item listing) record {
	return record{
		Product:  product,
		Category: category,
		ID:       firstNonEmpty(clean(string(item.IDSource)), clean(string(item.VictimID)), clean(string(item.ID))),
		Title:    firstNonEmpty(clean(string(item.PostTitle)), clean(string(item.Name))),
		Website:  clean(string(item.Website)),
		Group:    clean(string(item.GroupName)),
		Country:  clean(string(item.Country)),
		Date:     truncate(clean(string(item.Discovered)), 10),
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

// clean returns s as one short printable line. Control characters (ESC and the
// rest of C0/C1), format characters such as bidi overrides, and invalid UTF-8
// are dropped, whitespace is collapsed, and the length is capped. API text is
// untrusted, and it goes to a terminal.
func clean(s string) string {
	s = strings.ToValidUTF8(s, "")

	var builder strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			builder.WriteRune(' ')
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			continue
		default:
			builder.WriteRune(r)
		}
	}

	return truncate(strings.Join(strings.Fields(builder.String()), " "), maxTextRunes)
}

// truncate shortens s to at most limit runes.
func truncate(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}

	return string([]rune(s)[:limit])
}

// writeRecord prints one record and adds it to the file buffer. Every record
// names its product and category, so a mixed list stays readable.
func (dec *darkEyeClient) writeRecord(buffer *strings.Builder, n int, rec record) {
	theme.Greenf(":: %03d :: %-9s %s", n, "Product:", rec.Product).Fprintln(dec.out)
	fmt.Fprintf(buffer, ":: %03d :: %-9s %s\n", n, "Product:", rec.Product)

	line := func(label, value string) {
		if value == "" {
			return
		}
		theme.Greenf("          %-9s %s", label, value).Fprintln(dec.out)
		fmt.Fprintf(buffer, "          %-9s %s\n", label, value)
	}

	line("Category:", rec.Category)
	line("Title:", rec.Title)
	line("Website:", rec.Website)
	line("Group:", rec.Group)
	line("Country:", rec.Country)
	line("Date:", rec.Date)
	line("ID:", rec.ID)
}
