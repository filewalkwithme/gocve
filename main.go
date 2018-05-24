package main

import (
	"database/sql"
	"flag"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// we are going to search for occurrences of CVE IDs on this repository
var repo string

func init() {
	flag.StringVar(&repo, "repo", "", "Target repository. We are going to search for occurrences of CVE IDs on this repository")
}

// https://cve.mitre.org/cve/identifiers/tech-guidance.html#extraction_or_parsing
var cveRegex = regexp.MustCompile(`(?i)(CVE-\d{4}-(0\d{3}|[1-9]\d{3,}))`)

type cveLinksMap map[string]map[string]bool

type cve struct {
	ID    string
	Score float32
}

func main() {
	flag.Parse()

	fmt.Println(repo)

	// Key:   CVE ID
	// Value: Array of links
	var cveLinks = make(cveLinksMap)

	// Open db connection
	db, err := sql.Open("sqlite3", "nvd/db/cve.sqlite3")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Search on NVD database
	err = searchNVD(db, cveLinks, repo)
	if err != nil {
		panic(err)
	}

	// Search on Github issues and pull requests
	err = searchGithub(cveLinks, repo)
	if err != nil {
		panic(err)
	}

	cveArray := []cve{}
	for cveID := range cveLinks {
		cve := &cve{ID: cveID}
		err := getDataFromNVD(db, cve)
		if err != nil {
			fmt.Printf("%v: %v\n", cve.ID, err)
			continue
		}
		cveArray = append(cveArray, *cve)
	}

	sort.Slice(cveArray, func(i int, j int) bool {
		return cveArray[i].Score > cveArray[j].Score
	})

	for _, cve := range cveArray {
		fmt.Printf("\n[score: %.2f] %s %s\n",
			cve.Score, pad(cve.ID, 20),
			fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%v", cve.ID))

		for link := range cveLinks[cve.ID] {
			fmt.Printf("%s%s\n", pad("", 35), link)
		}
	}
}

func pad(text string, size int) string {
	return text + strings.Repeat(" ", size-len(text))
}
