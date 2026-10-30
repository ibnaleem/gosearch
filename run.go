package main

import (
	"context"
	"fmt"
	"io"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/theme"
)

// runModules searches query with every module and prints each module's
// output under its own separator, in the order given
func runModules(ctx context.Context, w io.Writer, query string, newModules []func(io.Writer) modules.Module) []modules.Result {
	var results []modules.Result
	for _, newModule := range newModules {
		fmt.Fprintln(w, config.SEPERATOR)

		result, err := newModule(w).Search(ctx, query)
		if err != nil {
			theme.Redf("[x] %v", err).Fprintln(w)
			continue
		}

		if result != nil {
			results = append(results, *result)
		}
	}

	return results
}
