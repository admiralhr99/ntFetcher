package main

import (
	"bytes"
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

type PullRequestData struct {
	LastRun time.Time     `json:"last_run"`
	PRs     []PullRequest `json:"prs"`
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

	data, err := loadPreviousPRs(*outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading previous pull requests: %v\n", err)
		data = &PullRequestData{LastRun: time.Now().AddDate(0, -1, 0), PRs: []PullRequest{}}
	}

	newPRs, err := fetchNewPullRequests(ctx, client, owner, repo, data.LastRun, *silent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching new pull requests: %v\n", err)
		os.Exit(1)
	}

	if len(newPRs) > 0 {
		fmt.Println("New pull requests:")
		for _, pr := range newPRs {
			fmt.Printf("- %s\n", pr.Title)
		}

		if *download {
			if err := downloadYAMLFiles(newPRs); err != nil {
				fmt.Fprintf(os.Stderr, "Error downloading YAML files: %v\n", err)
			}
		}

		data.PRs = append(newPRs, data.PRs...)
		data.LastRun = time.Now()
		if err := writeToFile(data, *outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving pull requests: %v\n", err)
		}
	} else {
		fmt.Println("No new pull requests found.")
	}
}

func getPRSlice(prMap map[string]PullRequest) []PullRequest {
	prSlice := make([]PullRequest, 0, len(prMap))
	for _, pr := range prMap {
		prSlice = append(prSlice, pr)
	}
	return prSlice
}

func fetchNewPullRequests(ctx context.Context, client *github.Client, owner, repo string, since time.Time, silent bool) ([]PullRequest, error) {
	opts := &github.PullRequestListOptions{
		State:     "open",
		Sort:      "created",
		Direction: "desc",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	var newPRs []PullRequest

	for {
		prs, resp, err := client.PullRequests.List(ctx, owner, repo, opts)
		if err != nil {
			return nil, err
		}

		for _, pr := range prs {
			if pr.CreatedAt.After(since) && strings.Contains(strings.ToLower(*pr.Title), "cve") {
				newPR := PullRequest{
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
				}

				newPRs = append(newPRs, newPR)
				//if !silent {
				//	fmt.Printf("New PR: %s\n", newPR.Title)
				//}
			} else if pr.CreatedAt.Before(since) || pr.CreatedAt.Equal(since) {
				// We've reached PRs that are older than or equal to our last run, so we can stop
				return newPRs, nil
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return newPRs, nil
}

func loadPreviousPRs(filename string) (*PullRequestData, error) {
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return &PullRequestData{LastRun: time.Now().AddDate(0, -1, 0), PRs: []PullRequest{}}, nil
		}
		return nil, err
	}
	defer file.Close()

	var data PullRequestData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}

	return &data, nil
}

//func fetchPullRequests(ctx context.Context, client *github.Client, owner, repo string, since time.Time, outputFile string, silent bool) error {
//	opts := &github.PullRequestListOptions{
//		State:     "open",
//		Sort:      "created",
//		Direction: "desc",
//		ListOptions: github.ListOptions{
//			PerPage: 100,
//		},
//	}
//
//	var allPRs []PullRequest
//
//	for {
//		prs, resp, err := client.PullRequests.List(ctx, owner, repo, opts)
//		if err != nil {
//			return err
//		}
//
//		for _, pr := range prs {
//			if pr.CreatedAt.Before(since) {
//				break
//			}
//
//			if strings.Contains(strings.ToLower(*pr.Title), "cve") {
//				allPRs = append(allPRs, PullRequest{
//					Title:     *pr.Title,
//					CreatedAt: *pr.CreatedAt,
//					HTMLURL:   *pr.HTMLURL,
//					User: struct {
//						Login string `json:"login"`
//					}{
//						Login: *pr.User.Login,
//					},
//					Head: struct {
//						SHA string `json:"sha"`
//					}{
//						SHA: *pr.Head.SHA,
//					},
//				})
//
//				if !silent {
//					fmt.Printf("New PR: %s\n", *pr.Title)
//				}
//			}
//		}
//
//		if resp.NextPage == 0 {
//			break
//		}
//		opts.Page = resp.NextPage
//	}
//
//	return writeToFile(allPRs, outputFile)
//}

func writeToFile(data *PullRequestData, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func downloadYAMLFiles(prs []PullRequest) error {
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
		var remoteContent []byte
		for _, path := range paths {
			url := fmt.Sprintf("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/%s/%s/%s/%s",
				pr.Head.SHA,
				path,
				year,
				filename)

			content, err := fetchFileContent(url)
			if err == nil {
				downloadedURL = url
				remoteContent = content
				break
			}
		}

		// If standard paths fail, try root with uppercase filename
		if downloadedURL == "" {
			url := fmt.Sprintf("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/%s/%s",
				pr.Head.SHA,
				filename)

			content, err := fetchFileContent(url)
			if err == nil {
				downloadedURL = url
				remoteContent = content
			}
		}

		// If uppercase in root fails, try lowercase in root
		if downloadedURL == "" {
			url := fmt.Sprintf("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/%s/%s",
				pr.Head.SHA,
				lowercaseFilename)

			content, err := fetchFileContent(url)
			if err == nil {
				downloadedURL = url
				remoteContent = content
			}
		}

		if downloadedURL != "" {
			if shouldUpdateFile(filename, remoteContent) {
				if err := os.WriteFile(filename, remoteContent, 0644); err != nil {
					fmt.Printf("Failed to write file %s: %v\n", filename, err)
				} else {
					fmt.Printf("Updated: %s\n", downloadedURL)
				}
			} else {
				fmt.Printf("Skipped: %s (No changes)\n", filename)
			}
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

func fetchFileContent(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func shouldUpdateFile(filename string, remoteContent []byte) bool {
	localContent, err := os.ReadFile(filename)
	if err != nil {
		// File doesn't exist locally, should download
		return true
	}

	// Compare content
	return !bytes.Equal(localContent, remoteContent)
}
