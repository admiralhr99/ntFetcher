package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v38/github"
	"golang.org/x/oauth2"
)

const (
	owner = "projectdiscovery"
	repo  = "nuclei-templates"
)

var (
	silent     bool
	logger     *log.Logger
	httpClient *http.Client
)

func main() {
	var downloadDir string
	var proxyURL string
	flag.StringVar(&downloadDir, "dir", ".", "Directory to download YAML files (default: current directory)")
	flag.StringVar(&proxyURL, "proxy", "", "HTTP proxy URL (optional)")
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

	// Set up HTTP client with proxy and TLS config
	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	if proxyURL != "" {
		proxyURLParsed, err := url.Parse(proxyURL)
		if err != nil {
			logger.Fatalf("Invalid proxy URL: %v", err)
		}
		httpClient.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURLParsed)
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	tc.Transport = httpClient.Transport
	client := github.NewClient(tc)

	newCVEs, err := fetchNewCVEs(ctx, client)
	if err != nil {
		logger.Fatalf("Error fetching new CVEs: %v", err)
	}

	downloadedCount := 0
	for _, cve := range newCVEs {
		err = downloadYAMLFiles(ctx, client, cve, downloadDir)
		if err != nil {
			logger.Printf("Error downloading YAML files for %s: %v", cve, err)
		} else {
			downloadedCount++
		}
	}

	if !silent {
		logger.Printf("Finished processing. Downloaded YAML files for %d new CVEs.", downloadedCount)
	}
}

func fetchNewCVEs(ctx context.Context, client *github.Client) ([]string, error) {
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
				if cve != "" {
					newCVEs = append(newCVEs, cve)
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

func extractCVE(title string) string {
	re := regexp.MustCompile(`CVE-\d{4}-\d+`)
	match := re.FindString(title)
	return match
}

func downloadYAMLFiles(ctx context.Context, client *github.Client, cve, downloadDir string) error {
	opt := &github.SearchOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	query := fmt.Sprintf("repo:%s/%s filename:%s.yaml path:cves", owner, repo, cve)
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
	resp, err := httpClient.Get(url)
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
