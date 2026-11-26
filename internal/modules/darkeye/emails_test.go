package darkeye

import (
	"reflect"
	"testing"
)

func TestCommonEmails(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     []string
	}{
		{
			name:     "one address per common provider",
			username: "hubwub2012",
			want: []string{
				"hubwub2012@gmail.com",
				"hubwub2012@yahoo.com",
				"hubwub2012@hotmail.com",
				"hubwub2012@outlook.com",
				"hubwub2012@icloud.com",
			},
		},
		{
			name:     "a username that is already an address gets none",
			username: "bob@gmail.com",
			want:     nil,
		},
		{
			name:     "a username with whitespace gets none",
			username: "bob smith",
			want:     nil,
		},
		{
			name:     "an empty username gets none",
			username: "",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commonEmails(tt.username)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("commonEmails(%q) = %v, want %v", tt.username, got, tt.want)
			}
		})
	}
}
