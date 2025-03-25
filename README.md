# ntFetcher: Nuclei Templates Pull Request Fetcher

ntFetcher is a Go application designed to fetch and track new CVE-related pull requests from the [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) repository. It helps security researchers and developers stay up-to-date with the latest CVE templates.

## Features

- Fetches new CVE-related pull requests
- Downloads associated YAML files for new pull requests
- Continuous monitoring mode for automated checking
- Self-update capability
- Custom download directory support
- Integration-friendly output for use with notification tools

## Installation

### Using Go Install

```bash
go install github.com/admiralhr99/ntFetcher@latest
```

### From Source

1. Ensure you have Go installed on your system. If not, download and install it from [golang.org](https://golang.org/).

2. Clone this repository

3. Build the application:
```bash
cd ntFetcher
go build
```

## Usage

### Basic Usage

```bash
# Display current version
ntFetcher -version

# Check for updates to ntFetcher
ntFetcher -update

# Fetch new pull requests and display them
ntFetcher

# Fetch new pull requests and download associated YAML files
ntFetcher -download

# Specify a custom output file
ntFetcher -output custom_output.json

# Run in silent mode
ntFetcher -silent

# Specify a custom download directory
ntFetcher -download -dir ./templates

# Run in continuous mode (checks every 24 hours)
ntFetcher -continuous

# Run in continuous mode with custom interval (e.g., 12 hours)
ntFetcher -continuous -interval 12h
```

## Examples

1. Set up a continuous monitor that downloads new CVE templates:
```bash
ntFetcher -continuous -download -dir ./cve-templates
```

2. Run in silent mode and save output to a custom file:
```bash
ntFetcher -silent -output custom_output.json -download
```

3. Run as a daily job to check for new templates:
```bash
ntFetcher -download -dir ./templates
```

## Integration with Notify

You can easily integrate ntFetcher with ProjectDiscovery's notify tool:

```bash
ntFetcher -silent | notify
```

## Version History

- v0.2.2: fix -update bug
- v0.2.1: edit update message
- v0.2.0: Added continuous mode, custom download directory, self-update functionality
- v0.1.0: Initial release