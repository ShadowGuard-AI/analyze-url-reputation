![Banner](banner.png)

# analyze-url-reputation
Checks one URL against the URLhaus threat feed and, when the operator sets a VIRUSTOTAL_API_KEY environment variable, against VirusTotal, and writes the result to a CSV report. - Focused on Data analysis and reporting

## Match types

The feed is parsed as CSV and the URL is compared against the url field of each listed row.

- `exact`, confidence `high`: the URL is equal to a listed URL.
- `substring`, confidence `low`: the URL and a listed URL overlap only in part, one containing the other. A prefix of a listed URL, or a bare domain root of one, is a substring match, not an exact match. The listed URL that overlapped is recorded as matched_url.

No entry in threat_feed_matches means no listed URL matched exactly or in part, in a feed that was fetched.

## Check status

The report records feed_fetch_succeeded, virustotal_checked, and check_status. check_status is `checked` when at least one source answered, meaning a feed was fetched or a VirusTotal result came back. When every feed fetch fails and no VirusTotal result is obtained, the URL was checked against nothing: the report records check_status as `not_checked` and the run exits 1.

## Install
`git clone https://github.com/ShadowStrikeHQ/analyze-url-reputation`

## Usage
`./analyze-url-reputation [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: Output file path for the CSV report. Defaults to url_analysis_report.csv.
- `-v`: Enable verbose logging.

## License
Copyright (c) ShadowStrikeHQ
