package search

import "testing"

// The cases below are ported from TestBuildURL and TestCanBuildURL on main.
// They guard the code that stops a username from being injected into the
// host, path or query string of a site URL.

func TestBuildSiteURL(t *testing.T) {
	sc := &searchClient{}

	cases := []struct {
		template, field, want string
	}{
		{"https://site/{}", "a/b?x=1#frag", "https://site/a%2Fb%3Fx=1%23frag"},
		{"https://site/{}", "john doe", "https://site/john%20doe"},
		{"https://site/user?id={}", "a/b?x=1#frag", "https://site/user?id=a%2Fb%3Fx%3D1%23frag"},
		{"https://site/user?id={}", "a&admin=1", "https://site/user?id=a%26admin%3D1"},
		{"https://{}.tumblr.com", "john", "https://john.tumblr.com"},
		{"https://site/about", "john", "https://site/about"},
	}

	for _, c := range cases {
		got, err := sc.buildSiteURL(c.template, c.field)
		if err != nil {
			t.Fatalf("buildSiteURL(%q, %q) error: %v", c.template, c.field, err)
		}

		if got != c.want {
			t.Errorf("buildSiteURL(%q, %q) = %q, want %q", c.template, c.field, got, c.want)
		}
	}
}

func TestCanBuildSiteURL(t *testing.T) {
	sc := &searchClient{}

	cases := []struct {
		template, field string
		want            bool
	}{
		{"https://{}.tumblr.com", "john-doe", true},
		{"https://{}.tumblr.com", "a/b", false},
		{"https://{}.tumblr.com", "a.b", false},
		{"https://{}", "john", true},
		{"https://site/{}", "a/b", true},
		{"", "a/b", true},
	}

	for _, c := range cases {
		if got := sc.canBuildSiteURL(c.template, c.field); got != c.want {
			t.Errorf("canBuildSiteURL(%q, %q) = %v, want %v", c.template, c.field, got, c.want)
		}
	}
}
