package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v39/github"
)

type PullRequest struct {
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
	HTMLURL   string    `json:"html_url"`
	User      struct {
		Login string `json:"login"`
	} `json:"user"`
	Head struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

func main() {
	owner := "projectdiscovery"
	repo := "nuclei-templates"

	outputFile := flag.String("output", "pull_requests.json", "Output file for pull requests")
	silent := flag.Bool("silent", false, "Silent mode")
	download := flag.Bool("download", false, "Download YAML files")
	flag.Parse()

	client := github.NewClient(nil)
	ctx := context.Background()

	oneMonthAgo := time.Now().AddDate(0, -1, 0)

	if err := fetchPullRequests(ctx, client, owner, repo, oneMonthAgo, *outputFile, *silent); err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching pull requests: %v\n", err)
		os.Exit(1)
	}

	if *download {
		if err := downloadYAMLFiles(*outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error downloading YAML files: %v\n", err)
			os.Exit(1)
		}
	}
}

func fetchPullRequests(ctx context.Context, client *github.Client, owner, repo string, since time.Time, outputFile string, silent bool) error {
	opts := &github.PullRequestListOptions{
		State:     "open",
		Sort:      "created",
		Direction: "desc",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	var allPRs []PullRequest

	for {
		prs, resp, err := client.PullRequests.List(ctx, owner, repo, opts)
		if err != nil {
			return err
		}

		for _, pr := range prs {
			if pr.CreatedAt.Before(since) {
				break
			}

			if strings.Contains(strings.ToLower(*pr.Title), "cve") {
				allPRs = append(allPRs, PullRequest{
					Title:     *pr.Title,
					CreatedAt: *pr.CreatedAt,
					HTMLURL:   *pr.HTMLURL,
					User: struct {
						Login string `json:"login"`
					}{
						Login: *pr.User.Login,
					},
					Head: struct {
						SHA string `json:"sha"`
					}{
						SHA: *pr.Head.SHA,
					},
				})

				if !silent {
					fmt.Printf("New PR: %s\n", *pr.Title)
				}
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return writeToFile(allPRs, outputFile)
}

func writeToFile(prs []PullRequest, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(prs)
}

func downloadYAMLFiles(inputFile string) error {
	file, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	var prs []PullRequest
	if err := json.NewDecoder(file).Decode(&prs); err != nil {
		return err
	}

	paths := []string{
		"http/cves",
		"network/cves",
		"passive/cves",
		"code/cves",
		"headless/cves",
		"dast/cves",
		"javascript/cves",
	}

	for _, pr := range prs {
		cve := extractCVE(pr.Title)
		if cve == "" {
			fmt.Printf("Skipping PR: %s (No CVE found in title)\n", pr.Title)
			continue
		}

		year := extractYear(cve)
		if year == "" {
			fmt.Printf("Skipping PR: %s (No year found in CVE)\n", pr.Title)
			continue
		}

		cveUpper := strings.ToUpper(strings.TrimSuffix(cve, ".yaml"))
		filename := cveUpper + ".yaml"
		lowercaseFilename := strings.ToLower(cveUpper) + ".yaml"

		var downloadedURL string
		for _, path := range paths {
			url := fmt.Sprintf("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/%s/%s/%s/%s",
				pr.Head.SHA,
				path,
				year,
				filename)

			if err := downloadFile(url, filename); err == nil {
				downloadedURL = url
				break
			}
		}

		// If standard paths fail, try root with uppercase filename
		if downloadedURL == "" {
			url := fmt.Sprintf("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/%s/%s",
				pr.Head.SHA,
				filename)

			if err := downloadFile(url, filename); err == nil {
				downloadedURL = url
			}
		}

		// If uppercase in root fails, try lowercase in root
		if downloadedURL == "" {
			url := fmt.Sprintf("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/%s/%s",
				pr.Head.SHA,
				lowercaseFilename)

			if err := downloadFile(url, filename); err == nil {
				downloadedURL = url
			}
		}

		if downloadedURL != "" {
			fmt.Printf("Downloaded: %s\n", downloadedURL)
		} else {
			fmt.Printf("Failed to download %s from any path\n", filename)
		}
	}

	return nil
}

func extractCVE(title string) string {
	// First, try to find CVE pattern in the whole string
	re := regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)
	match := re.FindString(title)
	if match != "" {
		return strings.TrimSuffix(match, ".yaml")
	}

	// If no match found, split by common delimiters and check each part
	parts := strings.FieldsFunc(title, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == ':'
	})
	//parts := strings.Fields(title)
	for _, part := range parts {
		if strings.HasPrefix(strings.ToUpper(part), "CVE-") {
			return strings.TrimSuffix(part, ".yaml")
		}
	}
	return ""
}

func extractYear(cve string) string {
	parts := strings.Split(cve, "-")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func downloadFile(url, filename string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
