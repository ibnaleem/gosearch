package modules

import (
	"context"
	"fmt"
	"net/http"
)

type Module interface {
	Name() string
	Search(ctx context.Context, query string) (*Result, error)
}

type Result struct {
	Module  string
	Summary string
}

func CheckStatus(module, function string, status int) error {
	switch {
	case status == http.StatusTooManyRequests || status == http.StatusForbidden:
		return fmt.Errorf("%s(%s): rate limit exceeded or access denied (HTTP %d)", module, function, status)
	case status >= 400 && status != http.StatusNotFound:
		return fmt.Errorf("%s(%s): unexpected status %d", module, function, status)
	}

	return nil
}
