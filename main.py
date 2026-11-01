import argparse
import csv
import io
import logging
import sys
import pandas as pd
import requests
import os
import json
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# API Keys (Ideally, these should be sourced from environment variables or a secure configuration file)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")  # Example: export VIRUSTOTAL_API_KEY="your_api_key"
# Other API keys for other services (e.g., AbuseIPDB, etc.) can be added similarly

# List of threat intelligence feed URLs (example)
THREAT_FEEDS = [
    "https://urlhaus.abuse.ch/downloads/csv/",  # URLhaus
    # Add more threat feeds here
]

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Analyze URL reputation using threat intelligence feeds and VirusTotal.")
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument("-o", "--output", help="Output file path (CSV format).", default="url_analysis_report.csv")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return parser

def is_valid_url(url):
    """
    Validates a URL to ensure it's properly formatted.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        # http and https only: a bare scheme plus netloc test also passed
        # ftp and file style strings, which the feed check cannot fetch in
        # the way the report implies.
        return result.scheme in ("http", "https") and bool(result.netloc)
    except ValueError:
        return False

def match_url_against_feed_text(url, feed_text):
    """
    Matches a URL against the listed URLs in one feed's CSV text.

    The feed is parsed as CSV and the URL is compared against the url
    field of each row (the third column in the URLhaus layout; comment
    lines and a header row are skipped). Two match types are returned:

    - "exact" with confidence "high": the URL is equal to a listed URL.
    - "substring" with confidence "low": the URL and a listed URL
      overlap only in part, one containing the other. A prefix of a
      listed URL and a bare domain root are substring matches, not
      exact ones.

    Returns a dict with feed match fields, or None when no listed URL
    is an exact match or a partial overlap.
    """
    substring_match = None
    reader = csv.reader(io.StringIO(feed_text))
    for row in reader:
        if not row or len(row) < 3:
            continue
        if row[0].strip().startswith("#") or row[2].strip().lower() == "url":
            continue
        listed_url = row[2].strip()
        if not listed_url:
            continue
        if url == listed_url:
            return {"match_type": "exact", "confidence": "high", "matched_url": listed_url}
        if substring_match is None and (url in listed_url or listed_url in url):
            substring_match = {"match_type": "substring", "confidence": "low", "matched_url": listed_url}
    return substring_match


def check_url_against_threat_feeds(url, threat_feeds):
    """
    Checks a URL against a list of threat intelligence feeds.

    Args:
        url (str): The URL to check.
        threat_feeds (list): A list of threat intelligence feed URLs.

    Returns:
        tuple: A pair (matches, feed_fetch_succeeded). matches is a list
            of dictionaries describing each match found; it is empty
            when no feed listed the URL. feed_fetch_succeeded is True
            when at least one feed was fetched and parsed, and False
            when every fetch failed, so a caller can tell "checked, no
            match" apart from "not checked at all". A failed fetch is
            never reported as a successful no match result.
    """
    matches = []
    feed_fetch_succeeded = False
    for feed_url in threat_feeds:
        try:
            logging.info(f"Checking against threat feed: {feed_url}")
            # No timeout here once let a hung feed host stall the whole
            # run; the feed is a large CSV and 30 seconds is the budget.
            response = requests.get(feed_url, timeout=30)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            # The whole feed is downloaded and parsed again on every
            # single URL check, with no caching between runs. For one
            # URL that is merely wasteful; in a loop over many URLs it
            # is the dominant cost and hard on the feed host.
            feed_fetch_succeeded = True

            match = match_url_against_feed_text(url, response.text)
            if match:
                logging.warning(f"URL found in threat feed: {feed_url} ({match['match_type']})")
                matches.append({"feed": feed_url, **match})
            else:
                logging.debug(f"URL not found in threat feed: {feed_url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching threat feed from {feed_url}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while processing {feed_url}: {e}")
    return matches, feed_fetch_succeeded

def analyze_url_with_virustotal(url, api_key):
    """
    Analyzes a URL using the VirusTotal API.

    Args:
        url (str): The URL to analyze.
        api_key (str): The VirusTotal API key.

    Returns:
        dict: A dictionary containing the VirusTotal analysis results. Returns None if an error occurs.
    """
    if not api_key:
        logging.warning("VirusTotal API key is not set. Skipping VirusTotal analysis.")
        return None

    # This identifier is a percent quoted URL. The API's documented
    # identifier for a URL is its base64 form or its hash, so this
    # request can come back not found for a URL the service knows
    # well, and that None reads the same as a URL with no data. I flag
    # it here as a known weakness of this lookup rather than a result
    # worth trusting at face value.
    url_id = requests.utils.quote(url)
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        json_response = response.json()
        logging.debug(f"VirusTotal API Response: {json_response}") # Log the full response for debugging

        if "data" in json_response:
            return json_response["data"]
        elif "error" in json_response:
            logging.error(f"VirusTotal API Error: {json_response['error']}")
            return None
        else:
            logging.error(f"Unexpected VirusTotal API response: {json_response}")
            return None

    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying VirusTotal API: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding VirusTotal API response: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during VirusTotal analysis: {e}")
        return None

def main():
    """
    Main function to orchestrate the URL analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url
    output_file = args.output

    if not is_valid_url(url):
        logging.error(f"Invalid URL: {url}")
        print("Error: Invalid URL. Please provide a valid URL.")
        sys.exit(1)

    logging.info(f"Analyzing URL: {url}")

    # Perform analysis
    threat_feed_matches, feed_fetch_succeeded = check_url_against_threat_feeds(url, THREAT_FEEDS)
    virustotal_analysis = analyze_url_with_virustotal(url, VIRUSTOTAL_API_KEY)

    # The URL counts as checked only when at least one source actually
    # answered: a feed that was fetched, or a VirusTotal result. When
    # every feed fetch failed and no VirusTotal result was obtained,
    # the report says so plainly and the run exits 1, instead of
    # presenting an empty match list as a completed check.
    checked = feed_fetch_succeeded or virustotal_analysis is not None

    # Prepare data for output
    report_data = {
        "url": url,
        "threat_feed_matches": threat_feed_matches,
        "virustotal_analysis": virustotal_analysis,
        "feed_fetch_succeeded": feed_fetch_succeeded,
        "virustotal_checked": virustotal_analysis is not None,
        "check_status": "checked" if checked else "not_checked"
    }

    # Create a Pandas DataFrame
    df = pd.DataFrame([report_data])

    # Convert the complex columns to string representation for CSV export
    df['threat_feed_matches'] = df['threat_feed_matches'].apply(lambda x: json.dumps(x))
    df['virustotal_analysis'] = df['virustotal_analysis'].apply(lambda x: json.dumps(x) if x is not None else None)


    # Export to CSV
    try:
        df.to_csv(output_file, index=False)
        logging.info(f"Analysis report saved to: {output_file}")
        print(f"Analysis report saved to: {output_file}")
    except Exception as e:
        logging.error(f"Error writing to CSV file: {e}")
        print(f"Error writing to CSV file: {e}")
        sys.exit(1)

    if not checked:
        logging.error("URL was not checked: every threat feed fetch failed and no VirusTotal result was obtained.")
        print("Error: URL was not checked: every threat feed fetch failed and no VirusTotal result was obtained. "
              "The report records check_status as not_checked.")
        sys.exit(1)


if __name__ == "__main__":
    main()
