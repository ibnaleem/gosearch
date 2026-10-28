// Created by github.com/ibnaleem & contributors
// Contribute & support: github.com/ibnaleem/gosearch

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/file"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/modules/breachdirectory"
	"github.com/ibnaleem/gosearch/internal/modules/github"
	"github.com/ibnaleem/gosearch/internal/modules/gravatar"
	"github.com/ibnaleem/gosearch/internal/modules/hudsonrock"
	"github.com/ibnaleem/gosearch/internal/modules/keybase"
	"github.com/ibnaleem/gosearch/internal/modules/proxynova"
	"github.com/ibnaleem/gosearch/internal/modules/search"
	"github.com/ibnaleem/gosearch/internal/modules/weakpass"
	"github.com/ibnaleem/gosearch/internal/theme"
	"github.com/inancgumus/screen"
	"github.com/joho/godotenv"
)

var (
	username              string
	outputPath            string
	breachDirectoryAPIKey string
	noFalsePositive       bool
)

func init() {
	godotenv.Load()

	flag.StringVar(&username, "u", "", "Username to search")
	flag.StringVar(&username, "username", "", "Username to search")

	flag.StringVar(&outputPath, "o", ".", "Directory to save the output files (default: current directory)")
	flag.StringVar(&outputPath, "output", ".", "Directory to save the output files (default: current directory)")

	flag.StringVar(&breachDirectoryAPIKey, "bd", "", "Search Breach Directory with an API Key")
	flag.StringVar(&breachDirectoryAPIKey, "breach-directory", "", "Search Breach Directory with an API Key")

	flag.BoolVar(&noFalsePositive, "nfp", false, "Do not show false positives")
	flag.BoolVar(&noFalsePositive, "no-false-positives", false, "Do not show false positives")
}

func main() {
	flag.Parse()

	if username == "" {
		fmt.Fprintln(os.Stderr, "Usage: gosearch -u <username>")
		fmt.Fprintln(os.Stderr, "For help: gosearch -h")
		fmt.Fprintln(os.Stderr, "Issues: https://github.com/ibnaleem/gosearch/issues")
		os.Exit(1)
	}

	screen.Clear()

	fmt.Print(config.ASCII)
	fmt.Println(config.VERSION)
	fmt.Println(config.SEPERATOR)
	fmt.Printf(":: %-38s: %s\n", "Query ", username)

	if noFalsePositive {
		fmt.Printf(":: %-38s: %v\n", "No False Positives", noFalsePositive)
	}

	fileWriter := file.NewFileWriter(outputPath)
	hashCracker := weakpass.NewHashCracker()

	var clients []modules.Module
	clients = append(clients, gravatar.NewGravatarClient(fileWriter))
	clients = append(clients, hudsonrock.NewHudsonRockClient(fileWriter))
	clients = append(clients, keybase.NewKeyBaseClient(fileWriter))
	clients = append(clients, proxynova.NewProxyNovaClient(fileWriter))
	clients = append(clients, github.NewGitHubClient(fileWriter))
	clients = append(clients, breachdirectory.NewBreachDirectoryClient(fileWriter, hashCracker, breachDirectoryAPIKey))
	clients = append(clients, search.NewSearchClient(fileWriter, noFalsePositive))

	startAt := time.Now()

	var results []modules.Result
	for _, client := range clients {
		fmt.Println(config.SEPERATOR)

		result, err := client.Search(context.Background(), username)
		if err != nil {
			theme.Redf("[x] %v", err).Println()
			continue
		}

		if result != nil {
			results = append(results, *result)
		}
	}

	fmt.Println(config.SEPERATOR)
	fmt.Println(":: RESULTS ::")
	fmt.Println(config.SEPERATOR)

	for _, result := range results {
		fmt.Printf(":: %-38s: %s\n", result.Module, result.Summary)
	}

	fmt.Println(config.SEPERATOR)
	fmt.Printf(":: %-38s: %s\n", "Saved to ", outputPath)
	fmt.Printf(":: %-38s: %s\n", "Completed in", time.Since(startAt).Round(time.Millisecond))

	fmt.Println(config.SEPERATOR)

	os.Exit(0)
}
