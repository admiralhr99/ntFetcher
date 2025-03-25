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
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-github/v39/github"
)

// Version information
// git tag -a v0.2.0 -m "v0.2.0"
const (
	Version = "0.2.0"
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

	// Command line flags
	outputFile := flag.String("output", "pull_requests.json", "Output file for pull requests")
	silent := flag.Bool("silent", false, "Silent mode")
	download := flag.Bool("download", false, "Download YAML files")
	update := flag.Bool("update", false, "Check for updates to ntFetcher")
	downloadDir := flag.String("dir", ".", "Directory to download YAML files")
	continuous := flag.Bool("continuous", false, "Continuously check for new PRs (interval: 24h)")
	version := flag.Bool("version", false, "Display version information")
	interval := flag.Duration("interval", 24*time.Hour, "Interval for continuous mode")
	flag.Parse()

	if *version {
		fmt.Printf("ntFetcher version %s\n", Version)
		return
	}

	if *update {
		checkForUpdates(owner)
		return
	}

	// Ensure download directory exists
	if *download {
		if err := os.MkdirAll(*downloadDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating download directory: %v\n", err)
			os.Exit(1)
		}
	}

	// Set up GitHub client
	client := github.NewClient(nil)
	ctx := context.Background()

	// If continuous mode is enabled, set up signal handling
	if *continuous {
		fmt.Println("Running in continuous mode. Press Ctrl+C to exit.")

		// Create a channel to handle OS signals
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

		// Create a ticker for the specified interval
		ticker := time.NewTicker(*interval)
		defer ticker.Stop()

		// Run the first check immediately
		runCheck(ctx, client, owner, repo, *outputFile, *silent, *download, *downloadDir)

		// Then continue checking at intervals until interrupted
		for {
			select {
			case <-ticker.C:
				runCheck(ctx, client, owner, repo, *outputFile, *silent, *download, *downloadDir)
			case <-sigs:
				fmt.Println("\nReceived interrupt signal. Exiting...")
				return
			}
		}
	} else {
		// Single run mode
		runCheck(ctx, client, owner, repo, *outputFile, *silent, *download, *downloadDir)
	}
}

// runCheck performs a single check for new PRs
func runCheck(ctx context.Context, client *github.Client, owner, repo, outputFile string, silent, download bool, downloadDir string) {
	data, err := loadPreviousPRs(outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading previous pull requests: %v\n", err)
		data = &PullRequestData{LastRun: time.Now().AddDate(0, -1, 0), PRs: []PullRequest{}}
	}

	newPRs, err := fetchNewPullRequests(ctx, client, owner, repo, data.LastRun, silent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching new pull requests: %v\n", err)
		return
	}

	if len(newPRs) > 0 {
		if !silent {
			fmt.Printf("[%s] Found %d new pull requests:\n", time.Now().Format("2006-01-02 15:04:05"), len(newPRs))
			for _, pr := range newPRs {
				fmt.Printf("- %s\n", pr.Title)
			}
		}

		if download {
			if err := downloadYAMLFiles(newPRs, downloadDir); err != nil {
				fmt.Fprintf(os.Stderr, "Error downloading YAML files: %v\n", err)
			}
		}

		data.PRs = append(newPRs, data.PRs...)
		data.LastRun = time.Now()
		if err := writeToFile(data, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving pull requests: %v\n", err)
		}
	} else if !silent {
		fmt.Printf("[%s] No new pull requests found.\n", time.Now().Format("2006-01-02 15:04:05"))
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

func downloadYAMLFiles(prs []PullRequest, downloadDir string) error {
	paths := []string{
		"http/cves",
		"network/cves",
		"passive/cves",
		"code/cves",
		"headless/cves",
		"dast/cves",
		"javascript/cves",
		"cloud/kubernetes/cves",
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
		localFilePath := filepath.Join(downloadDir, filename)

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
			if shouldUpdateFile(localFilePath, remoteContent) {
				if err := os.WriteFile(localFilePath, remoteContent, 0644); err != nil {
					fmt.Printf("Failed to write file %s: %v\n", localFilePath, err)
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

// checkForUpdates checks GitHub for a newer version of ntFetcher
func checkForUpdates(username string) {
	// Change this to your repository name
	repoName := "ntFetcher"

	fmt.Println("Checking for updates...")

	// Construct the URL to check for releases
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", username, repoName)

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error checking for updates: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			fmt.Println("No releases found. You might need to create your first GitHub release.")
			return
		}
		fmt.Printf("Error checking for updates: HTTP status %d\n", resp.StatusCode)
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		fmt.Printf("Error parsing release information: %v\n", err)
		return
	}

	// Remove 'v' prefix if present for comparison
	remoteVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := Version

	if remoteVersion > currentVersion {
		fmt.Printf("A new version is available: %s (current: %s)\n", remoteVersion, currentVersion)
		fmt.Println("Installing update...")

		// Run go install command to update
		installCmd := exec.Command("go", "install", "github.com/admiralhr99/ntFetcher@latest")
		output, err := installCmd.CombinedOutput()

		if err != nil {
			fmt.Printf("Update failed: %v\n", err)
			fmt.Printf("Command output: %s\n", string(output))
			fmt.Println("You can manually update by running: go install github.com/admiralhr99/ntFetcher@latest")
			return
		}

		fmt.Println("Update successful! Please restart ntFetcher to use the new version.")
	} else {
		fmt.Printf("You are already running the latest version (%s)\n", currentVersion)
	}
}
