package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ibnaleem/gosearch/internal/modules"
)

type fakeModule struct {
	out   io.Writer
	name  string
	delay time.Duration
	err   error
}

func (f fakeModule) Name() string { return f.name }

func (f fakeModule) Search(ctx context.Context, query string) (*modules.Result, error) {
	fmt.Fprintf(f.out, "<%s>", f.name)
	time.Sleep(f.delay)
	if f.err != nil {
		return nil, f.err
	}
	return &modules.Result{Module: f.name, Summary: "ok"}, nil
}

func fake(name string, delay time.Duration, err error) func(io.Writer) modules.Module {
	return func(out io.Writer) modules.Module {
		return fakeModule{out: out, name: name, delay: delay, err: err}
	}
}

func TestRunModulesRunsConcurrentlyAndKeepsOrder(t *testing.T) {
	var out bytes.Buffer
	start := time.Now()
	results := runModules(context.Background(), &out, "john", []func(io.Writer) modules.Module{
		fake("slow", 400*time.Millisecond, nil),
		fake("broken", 300*time.Millisecond, errors.New("boom")),
		fake("fast", 200*time.Millisecond, nil),
	})
	elapsed := time.Since(start)

	if elapsed > 700*time.Millisecond {
		t.Fatalf("took %v; modules must run at the same time, not one after another", elapsed)
	}
	if len(results) != 2 || results[0].Module != "slow" || results[1].Module != "fast" {
		t.Fatalf("results = %+v, want slow then fast", results)
	}

	got := out.String()
	slow, broken, boom, fast := strings.Index(got, "<slow>"), strings.Index(got, "<broken>"), strings.Index(got, "boom"), strings.Index(got, "<fast>")
	if slow < 0 || broken < slow || boom < broken || fast < boom {
		t.Fatalf("output %q is not in module order", got)
	}
}
