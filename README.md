# ntFetcher: Nuclei Templates Pull Request Fetcher

ntFetcher is a Go application designed to fetch and track new CVE-related pull requests from the [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) repository. It helps security researchers and developers stay up-to-date with the latest CVE templates.

## Features

- Fetches new CVE-related pull requests
- Downloads associated YAML files for new pull requests

## Installation

1. Ensure you have Go installed on your system. If not, download and install it from [golang.org](https://golang.org/).

2. Clone this repository

3. `cd ntFetcher`

4. `go run main.go -download`


### Examples

1. Fetch new pull requests and display them:
```
go run main.go
```

2. Fetch new pull requests and download associated YAML files:
```
go run main.go -download
```

3. Run in silent mode and save output to a custom file:
```
go run main.go -silent -output custom_output.json
```
