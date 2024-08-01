package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v38/github"
	"golang.org/x/oauth2"
)

const (
	owner      = "projectdiscovery"
	repo       = "nuclei-templates"
	checkDelay = 1 * time.Minute
)

var (
	silent bool
	logger *log.Logger
)

func main() {
	var filename string
	var downloadDir string
	flag.StringVar(&filename, "file", "cve_titles.txt", "Filename to store CVE titles")
	flag.StringVar(&downloadDir, "dir", "", "Directory to download YAML files (optional)")
	flag.BoolVar(&silent, "silent", false, "Silent mode: don't print anything")
	flag.Parse()

	if silent {
		logger = log.New(io.Discard, "", 0)
	} else {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		logger.Fatal("GITHUB_TOKEN environment variable not set")
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	existingCVEs := loadExistingCVEs(filename)
	isFirstRun := len(existingCVEs) == 0

	for {
		newCVEs, err := fetchNewCVEs(ctx, client, isFirstRun, existingCVEs)
		if err != nil {
			logger.Printf("Error fetching new CVEs: %v", err)
			time.Sleep(checkDelay)
			continue
		}

		if len(newCVEs) > 0 {
			err = appendToFile(filename, newCVEs)
			if err != nil {
				logger.Printf("Error appending to file: %v", err)
			}

			if downloadDir != "" {
				for _, cve := range newCVEs {
					err = downloadYAMLFiles(ctx, client, cve, downloadDir)
					if err != nil {
						logger.Printf("Error downloading YAML files for %s: %v", cve, err)
					}
				}
			}

			existingCVEs = append(existingCVEs, newCVEs...)
		}

		isFirstRun = false
		time.Sleep(checkDelay)
	}
}

func loadExistingCVEs(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		return []string{}
	}
	defer file.Close()

	var cves []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if cve := extractCVE(scanner.Text()); cve != "" {
			cves = append(cves, cve)
		}
	}
	return cves
}

func extractCVE(title string) string {
	re := regexp.MustCompile(`CVE-\d{4}-\d+`)
	match := re.FindString(title)
	return match
}

func fetchNewCVEs(ctx context.Context, client *github.Client, isFirstRun bool, existingCVEs []string) ([]string, error) {
	var newCVEs []string
	oneMonthAgo := time.Now().AddDate(0, -1, 0)

	opt := &github.PullRequestListOptions{
		State:     "all",
		Sort:      "updated",
		Direction: "desc",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		prs, resp, err := client.PullRequests.List(ctx, owner, repo, opt)
		if err != nil {
			return nil, err
		}

		for _, pr := range prs {
			if pr.GetUpdatedAt().Before(oneMonthAgo) {
				return newCVEs, nil
			}

			if strings.Contains(strings.ToLower(pr.GetTitle()), "cve") {
				cve := extractCVE(pr.GetTitle())
				if cve != "" && !contains(existingCVEs, cve) {
					newCVEs = append(newCVEs, cve)
					logger.Printf("New CVE template: %s (#%d)\n", pr.GetTitle(), pr.GetNumber())
				}
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return newCVEs, nil
}

func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

func appendToFile(filename string, cves []string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, cve := range cves {
		if _, err := file.WriteString(cve + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func downloadYAMLFiles(ctx context.Context, client *github.Client, cve, downloadDir string) error {
	opt := &github.SearchOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	query := fmt.Sprintf("repo:%s/%s filename:%s.yaml", owner, repo, cve)
	for {
		result, resp, err := client.Search.Code(ctx, query, opt)
		if err != nil {
			return err
		}

		for _, file := range result.CodeResults {
			downloadURL := file.GetHTMLURL()
			downloadURL = strings.Replace(downloadURL, "github.com", "raw.githubusercontent.com", 1)
			downloadURL = strings.Replace(downloadURL, "/blob/", "/", 1)

			localPath := filepath.Join(downloadDir, filepath.Base(file.GetName()))
			err := downloadFile(downloadURL, localPath)
			if err != nil {
				logger.Printf("Error downloading file %s: %v", file.GetName(), err)
			} else if !silent {
				logger.Printf("Successfully downloaded: %s", localPath)
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return nil
}

func downloadFile(url, filePath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
