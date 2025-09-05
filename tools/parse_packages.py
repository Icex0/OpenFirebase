#!/usr/bin/env python3
"""Package Name Parser - Extracts and counts unique package names from a file,
then scrapes Google Play Store for contact emails and download counts.

Dependencies:
    pip install requests beautifulsoup4

Usage: python parse_packages.py <input_file>

Example format expected in file:
"Project ID: openfire-base (from package: com.openfire.base)"

Output example:
  5 - com.openfire.base [10 mln.+]
      Email: support@example.com
"""

import re
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup


def parse_package_names(file_path):
    """Parse package names from a file and return unique counts.
    
    Args:
        file_path (str): Path to the input file
        
    Returns:
        Counter: Dictionary-like object with package names and their counts

    """
    # Regular expression to match "from package: <package_name>)"
    pattern = r"\(from package:\s+([^)]+)\)"

    package_names = []

    try:
        with open(file_path, encoding="utf-8", errors="ignore") as file:
            for line_num, line in enumerate(file, 1):
                matches = re.findall(pattern, line)
                for match in matches:
                    # Clean up the package name (remove any trailing/leading whitespace)
                    package_name = match.strip()
                    if package_name:
                        package_names.append(package_name)

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return Counter()
    except Exception as e:
        print(f"Error reading file: {e}")
        return Counter()

    return Counter(package_names)


def scrape_info_from_play_store(package_name):
    """Scrape email address and download count from Google Play Store page for given package.
    
    Args:
        package_name (str): Android package name
        
    Returns:
        tuple: (email, download_count) - both str or None if not found

    """
    url = f"https://play.google.com/store/apps/details?id={quote(package_name)}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        print(f"  Scraping: {package_name}...", end=" ")
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")

        email = None
        download_count = None

        # Look for mailto links
        mailto_links = soup.find_all("a", href=re.compile(r"^mailto:"))
        if mailto_links:
            # Extract email from the first mailto link
            href = mailto_links[0].get("href")
            email_match = re.search(r"mailto:([^?&]+)", href)
            if email_match:
                email = email_match.group(1)

        # Look for download count in ClM7O divs
        clm7o_divs = soup.find_all("div", class_="ClM7O")
        for div in clm7o_divs:
            text = div.get_text(strip=True)
            # Check if this div contains download count (contains numbers and typical download suffixes)
            if re.search(r"\d+.*(?:mln|tys|k|\+|million|thousand)", text.lower()):
                download_count = text
                break

        results = []
        if email:
            results.append(f"Email: {email}")
        if download_count:
            results.append(f"Downloads: {download_count}")

        if results:
            print(f"✓ Found: {', '.join(results)}")
        else:
            print("✗ No info found")

        return email, download_count

    except requests.exceptions.RequestException as e:
        print(f"✗ Error: {e!s}")
        return None, None
    except Exception as e:
        print(f"✗ Parse error: {e!s}")
        return None, None


def main():
    """Main function to handle command line arguments and display results."""
    if len(sys.argv) != 2:
        print("Usage: python parse_packages.py <input_file>")
        print("\nExample:")
        print("python parse_packages.py results.txt")
        sys.exit(1)

    input_file = sys.argv[1]

    # Check if file exists
    if not Path(input_file).exists():
        print(f"Error: File '{input_file}' does not exist.")
        sys.exit(1)

    print(f"Parsing package names from: {input_file}")
    print("-" * 50)

    # Parse the file
    package_counts = parse_package_names(input_file)

    if not package_counts:
        print("No package names found in the file.")
        return

    # Display results
    print(f"Found {len(package_counts)} unique package names:\n")

    # Sort by count (descending) then by package name (ascending)
    sorted_packages = sorted(package_counts.items(), key=lambda x: (-x[1], x[0]))

    for package_name, count in sorted_packages:
        print(f"{count:3d} - {package_name}")

    print(f"\nTotal unique packages: {len(package_counts)}")
    print(f"Total occurrences: {sum(package_counts.values())}")

    # Now scrape info from Google Play Store
    print("\n" + "="*60)
    print("SCRAPING INFO FROM GOOGLE PLAY STORE")
    print("="*60)

    package_info = {}

    for i, (package_name, count) in enumerate(sorted_packages, 1):
        print(f"\n[{i}/{len(sorted_packages)}]", end=" ")
        email, download_count = scrape_info_from_play_store(package_name)
        package_info[package_name] = {"email": email, "downloads": download_count}

        # Be respectful to the server - add delay between requests
        if i < len(sorted_packages):
            time.sleep(1)

    # Display final results with all info
    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)

    packages_with_emails = 0
    packages_with_downloads = 0

    for package_name, count in sorted_packages:
        info = package_info.get(package_name, {})
        email = info.get("email")
        downloads = info.get("downloads")

        # Package line with downloads
        package_line = f"{count:3d} - {package_name}"
        if downloads:
            package_line += f" [{downloads}]"
            packages_with_downloads += 1
        print(package_line)

        # Email line
        if email:
            packages_with_emails += 1
            print(f"      Email: {email}")
        else:
            print("      Email: Not found\n")

    print("Summary:")
    print(f"  Total unique packages: {len(package_counts)}")
    print(f"  Packages with emails found: {packages_with_emails}")
    print(f"  Packages with download counts found: {packages_with_downloads}")
    print(f"  Email success rate: {packages_with_emails/len(package_counts)*100:.1f}%")
    print(f"  Download count success rate: {packages_with_downloads/len(package_counts)*100:.1f}%")

    # Collect all unique emails for BCC format
    unique_emails = set()
    for package_name, count in sorted_packages:
        info = package_info.get(package_name, {})
        email = info.get("email")
        if email:
            unique_emails.add(email)

    if unique_emails:
        print("\n" + "="*60)
        print("EMAILS FOR BCC (Copy & Paste Ready)")
        print("="*60)

        # Sort emails alphabetically for consistency
        sorted_emails = sorted(unique_emails)
        bcc_emails = "; ".join(sorted_emails)

        print(f"{bcc_emails}\n")
        print(f"Total unique emails ready for BCC: {len(unique_emails)}")
    else:
        print("\nNo emails found to format for BCC.")


if __name__ == "__main__":
    main()
