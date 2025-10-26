// Created by github.com/ibnaleem & contributors
// Contribute & support: github.com/ibnaleem/gosearch

package main

import (
	"os"
	"fmt"
	"log"
	"flag"
	"sync"
	"time"
	"strconv"
	"strings"
	
	"github.com/inancgumus/screen"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/olekukonko/tablewriter/renderer"
)

func main() {

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
		OutputDir = *outputFlag
	} else if *outputFlagLong != "" {
		OutputDir = *outputFlagLong
	} else {
		OutputDir = "."
	}

	var wg sync.WaitGroup

	data, err := UnmarshalJSON()
	if err != nil {
		fmt.Printf("Error unmarshalling json: %v\n", err)
		os.Exit(1)
	}

	screen.Clear()
	fmt.Print(ASCII)
	fmt.Println(VERSION)
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
	go Search(data, username, *noFalsePositivesFlag, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	wg.Add(1)
	WriteToFile(username, strings.Repeat("⎯", 85))
	Yellow("[*] Searching HudsonRock's Cybercrime Intelligence Database...").Println()
	go HudsonRock(username, &wg)
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
		go SearchBreachDirectory(username, apikey, &wg)
		wg.Wait()
	}

	fmt.Println()
	fmt.Println()

	wg.Add(1)
	WriteToFile(username, strings.Repeat("⎯", 85))
	go SearchProxyNova(username, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	domains := BuildDomains(username)
	wg.Add(1)
	go SearchDomains(username, domains, &wg)
	wg.Wait()

	fmt.Println()
	fmt.Println()

	elapsed := time.Since(start)

	table := tablewriter.NewTable(os.Stdout, tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{Borders: tw.BorderNone})))
	table.Append(Bold("Number of profiles found"), Red(count.Load()))
	table.Append(Bold("Total time taken"), Green(elapsed))
	if err := table.Render(); err != nil {
		log.Printf("table render failed: %v", err)
	}

	WriteToFile(username, ":: Number of profiles found              : "+strconv.Itoa(int(count.Load())))
	WriteToFile(username, ":: Total time taken                      : "+elapsed.String())
}