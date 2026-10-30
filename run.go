package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/theme"
)

// syncBuffer collects one module's output; modules like Search print from
// several goroutines at once
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

type moduleRun struct {
	out    syncBuffer
	done   chan struct{}
	result *modules.Result
	err    error
}

// runModules searches query with every module at once, then prints each
// module's output under its own separator in the order given, as soon as it
// and every module before it have finished
func runModules(ctx context.Context, w io.Writer, query string, newModules []func(io.Writer) modules.Module) []modules.Result {
	runs := make([]*moduleRun, len(newModules))
	for i, newModule := range newModules {
		run := &moduleRun{done: make(chan struct{})}
		runs[i] = run
		go func() {
			defer close(run.done)
			run.result, run.err = newModule(&run.out).Search(ctx, query)
		}()
	}

	var results []modules.Result
	for _, run := range runs {
		<-run.done
		fmt.Fprintln(w, config.SEPERATOR)
		w.Write(run.out.buf.Bytes())

		if run.err != nil {
			theme.Redf("[x] %v", run.err).Fprintln(w)
			continue
		}

		if run.result != nil {
			results = append(results, *run.result)
		}
	}

	return results
}
