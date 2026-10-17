package utils

import "testing"

func TestBuildURL(t *testing.T) {
	tests := []struct {
		template, username, want string
	}{
		{"https://site/{}", "a/b?x=1#frag", "https://site/a%2Fb%3Fx=1%23frag"},
		{"https://site/{}", "john doe", "https://site/john%20doe"},
		{"https://site/user?id={}", "a/b?x=1#frag", "https://site/user?id=a%2Fb%3Fx%3D1%23frag"},
		{"https://site/user?id={}", "a&admin=1", "https://site/user?id=a%26admin%3D1"},
		{"https://{}.tumblr.com", "john", "https://john.tumblr.com"},
		{"https://site/about", "john", "https://site/about"},
	}
	for _, tt := range tests {
		if got := BuildURL(tt.template, tt.username); got != tt.want {
			t.Errorf("BuildURL(%q, %q) = %q, want %q", tt.template, tt.username, got, tt.want)
		}
	}
}

func TestCanBuildURL(t *testing.T) {
	tests := []struct {
		template, username string
		want               bool
	}{
		{"https://{}.tumblr.com", "john-doe", true},
		{"https://{}.tumblr.com", "a/b", false},
		{"https://{}.tumblr.com", "a.b", false},
		{"https://{}", "john", true},
		{"https://site/{}", "a/b", true},
		{"", "a/b", true},
	}
	for _, tt := range tests {
		if got := CanBuildURL(tt.template, tt.username); got != tt.want {
			t.Errorf("CanBuildURL(%q, %q) = %v, want %v", tt.template, tt.username, got, tt.want)
		}
	}
}
