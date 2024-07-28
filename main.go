package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type PullRequest struct {
	ID     int    `json:"id"`
	Number int    `json:"number"`
	Title  string `json:"title"`
	User   struct {
		Login string `json:"login"`
	} `json:"user"`
	HTMLURL string `json:"html_url"`
}

type Commit struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit  struct {
		Message string `json:"message"`
	} `json:"commit"`
}

type PRInfo struct {
	PullRequest PullRequest `yaml:"pull_request"`
	Commits     []Commit    `yaml:"commits"`
}

func getPullRequests(apiURL, githubToken string) ([]PullRequest, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "token "+githubToken)
	req.Header.Add("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error fetching pull requests: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var pullRequests []PullRequest
	err = json.Unmarshal(body, &pullRequests)
	if err != nil {
		return nil, err
	}

	return pullRequests, nil
}

func getCommits(commitsURL, githubToken string) ([]Commit, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", commitsURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "token "+githubToken)
	req.Header.Add("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error fetching commits: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var commits []Commit
	err = json.Unmarshal(body, &commits)
	if err != nil {
		return nil, err
	}

	return commits, nil
}

func savePRInfo(pr PullRequest, commits []Commit) error {
	prInfo := PRInfo{
		PullRequest: pr,
		Commits:     commits,
	}

	data, err := yaml.Marshal(&prInfo)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("PR-%d.yaml", pr.Number)
	return ioutil.WriteFile(filename, data, 0644)
}

func main() {
	apiURL := flag.String("api-url", "", "GitHub API URL for pull requests")
	flag.Parse()

	if *apiURL == "" {
		fmt.Println("Error: API URL is required. Use --api-url flag.")
		flag.PrintDefaults()
		os.Exit(1)
	}

	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		fmt.Println("Error: GITHUB_TOKEN environment variable is not set.")
		os.Exit(1)
	}

	pullRequests, err := getPullRequests(*apiURL, githubToken)
	if err != nil {
		fmt.Printf("Error fetching pull requests: %v\n", err)
		return
	}

	for _, pr := range pullRequests {
		if strings.Contains(strings.ToUpper(pr.Title), "CVE") {
			fmt.Printf("Found CVE in PR #%d: %s\n", pr.Number, pr.Title)

			commitsURL := strings.Replace(*apiURL, "pulls", fmt.Sprintf("pulls/%d/commits", pr.Number), 1)
			commits, err := getCommits(commitsURL, githubToken)
			if err != nil {
				fmt.Printf("Error fetching commits for PR #%d: %v\n", pr.Number, err)
				continue
			}

			err = savePRInfo(pr, commits)
			if err != nil {
				fmt.Printf("Error saving PR info for PR #%d: %v\n", pr.Number, err)
			} else {
				fmt.Printf("Saved PR info for PR #%d\n", pr.Number)
			}
		}
	}
}
