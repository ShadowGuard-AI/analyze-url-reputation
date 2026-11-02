![The timetable archive with no legible word in it: an open spread with its red ribbon on the long table, stepped stacks, shelves of volumes band upon band](intro-banner.png)

# analyze-url-reputation

![The archive room late in the day with the name lettered on the one shelf end board at the right](banner.png)

![Stepped stack of timetable volumes, the top one open, a red ribbon falling down the front, the heading plate](logo.png)

![Archive scene in three depths: a headlamp grows and fades beyond the fixed gantry, window light shifts across the shelf bands, dust settles over the table](scene.svg)


# analyze-url-reputation
Checks one URL against the URLhaus threat feed and, when the operator sets a VIRUSTOTAL_API_KEY environment variable, against VirusTotal, and writes the result to a CSV report. - Focused on Data analysis and reporting


![Section divider](sep-light.svg)

## Match types

The feed is parsed as CSV and the URL is compared against the url field of each listed row.

- `exact`, confidence `high`: the URL is equal to a listed URL.
- `substring`, confidence `low`: the URL and a listed URL overlap only in part, one containing the other. A prefix of a listed URL, or a bare domain root of one, is a substring match, not an exact match. The listed URL that overlapped is recorded as matched_url.

> Archivist's slip: a prefix of a listed URL, or a bare domain root of one, is a substring match, not an exact match.

No entry in threat_feed_matches means no listed URL matched exactly or in part, in a feed that was fetched.

> Archivist's slip: an empty threat_feed_matches result means no listed URL matched in a feed that was fetched. The qualification is part of the finding.


![Section divider](sep-heavy.svg)

## Check status

The report records feed_fetch_succeeded, virustotal_checked, and check_status. check_status is `checked` when at least one source answered, meaning a feed was fetched or a VirusTotal result came back. When every feed fetch fails and no VirusTotal result is obtained, the URL was checked against nothing: the report records check_status as `not_checked` and the run exits 1.

> Archivist's slip: when no source answered, the report records check_status as not_checked and the run exits 1. A failed fetch is not a clean finding.


![Section divider](sep-light.svg)

## Install
`git clone https://github.com/ShadowStrikeHQ/analyze-url-reputation`


![Section divider](sep-light.svg)

## Usage
`./analyze-url-reputation [params]`


![Section divider](sep-heavy.svg)

## Parameters
- `-h`: Show help message and exit
- `-o`: Output file path for the CSV report. Defaults to url_analysis_report.csv.
- `-v`: Enable verbose logging.


![Section divider](sep-heavy.svg)

## License
Copyright (c) ShadowStrikeHQ
