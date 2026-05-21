// Created by github.com/ibnaleem & contributors
// Contribute & support: github.com/ibnaleem/gosearch

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/inancgumus/screen"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/joho/godotenv"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/modules/breachdirectory"
	github "github.com/ibnaleem/gosearch/internal/modules/github"
	"github.com/ibnaleem/gosearch/internal/modules/hudsonrock"
	"github.com/ibnaleem/gosearch/internal/modules/proxynova"
	"github.com/ibnaleem/gosearch/internal/search"
	"github.com/ibnaleem/gosearch/internal/theme"
	"github.com/ibnaleem/gosearch/internal/utils"
)

func main() {

	godotenv.Load() // silently ignored if no .env file

	var username string
	var apikey string

	usernameFlag := flag.String("u", "", "Username to search")
	usernameFlagLong := flag.String("username", "", "Username to search")
	noFalsePositivesFlag := flag.Bool("no-false-positives", false, "Do not show false positives")
	breachDirectoryAPIKey := flag.String("b", "", "Search Breach Directory with an API Key")
	breachDirectoryAPIKeyLong := flag.String("breach-directory", "", "Search Breach Directory with an API Key")
	outputFlag := flag.String("o", "", "Directory to save the output files (default: current directory)")
	outputFlagLong := flag.String("output", "", "Directory to save the output files (default: current directory)")

	flag.Parse()

	if *usernameFlag != "" {
		username = *usernameFlag
	} else if *usernameFlagLong != "" {
		username = *usernameFlagLong
	} else {
		fmt.Println("Usage: gosearch -u <username>\nIssues: https://github.com/ibnaleem/gosearch/issues")
		os.Exit(1)
	}

	if *outputFlag != "" {
		config.OutputDir = *outputFlag
	} else if *outputFlagLong != "" {
		config.OutputDir = *outputFlagLong
	}

	var wg sync.WaitGroup

	data, err := utils.UnmarshalJSON()
	if err != nil {
		fmt.Printf("Error unmarshalling json: %v\n", err)
		os.Exit(1)
	}

	screen.Clear()
	fmt.Print(config.ASCII)
	fmt.Println(config.VERSION)
	fmt.Println(strings.Repeat("⎯", 85))
	fmt.Println(":: Username                              : ", username)
	fmt.Println(":: Websites                              : ", len(data.Websites))

	if *noFalsePositivesFlag {
		fmt.Println(":: No False Positives                    : ", *noFalsePositivesFlag)
	}

	fmt.Println(strings.Repeat("⎯", 85))
	fmt.Println()

	if !*noFalsePositivesFlag {
		fmt.Println("[!] A yellow link indicates that I was unable to verify whether the username exists on the platform.")
	}

	start := time.Now()

	wg.Add(len(data.Websites))
	go search.Search(data, username, *noFalsePositivesFlag, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	github.DisplayEmailsFromCommits(username)

	fmt.Println()
	fmt.Println()

	github.DisplayGPGKeys(username)

	fmt.Println()
	fmt.Println()

	github.DisplaySSHKeys(username)

	fmt.Println()
	fmt.Println()

	wg.Add(1)
	utils.WriteToFile(username, strings.Repeat("⎯", 85))
	theme.Yellow("[*] Searching HudsonRock's Cybercrime Intelligence Database...").Println()
	go hudsonrock.HudsonRock(username, &wg)
	wg.Wait()

	if *breachDirectoryAPIKey != "" || *breachDirectoryAPIKeyLong != "" {
		if *breachDirectoryAPIKey != "" {
			apikey = *breachDirectoryAPIKey
		} else {
			apikey = *breachDirectoryAPIKeyLong
		}

		fmt.Println()
		fmt.Println()

		wg.Add(1)
		go breachdirectory.SearchBreachDirectory(username, apikey, &wg)
		wg.Wait()
	}

	fmt.Println()
	fmt.Println()

	wg.Add(1)
	utils.WriteToFile(username, strings.Repeat("⎯", 85))
	go proxynova.SearchProxyNova(username, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	domains := utils.BuildDomains(username)
	wg.Add(1)
	go search.SearchDomains(username, domains, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	elapsed := time.Since(start)

	table := tablewriter.NewTable(os.Stdout, tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{Borders: tw.BorderNone})))
	table.Append(theme.Bold("Number of profiles found"), theme.Red(config.Count.Load()))
	table.Append(theme.Bold("Total time taken"), theme.Green(elapsed))
	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}

	utils.WriteToFile(username, ":: Number of profiles found              : "+strconv.Itoa(int(config.Count.Load())))
	utils.WriteToFile(username, ":: Total time taken                      : "+elapsed.String())
}
