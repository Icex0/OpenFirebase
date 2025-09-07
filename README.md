<div align="center">
  <img src="assets/images/OpenFireBase_logo.png" alt="OpenFirebase Logo" />
</div>

<div align="center">
  <img src="assets/images/header.png" alt="OpenFirebase" width="640" />
</div>

<div align="center">

[![GitHub stars](https://img.shields.io/github/stars/Icex0/OpenFirebase?style=flat-square)](https://github.com/Icex0/OpenFirebase/stargazers)
[![License](https://img.shields.io/github/license/Icex0/OpenFirebase?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square)](https://www.python.org)
[![GitHub issues](https://img.shields.io/github/issues/Icex0/OpenFirebase?style=flat-square)](https://github.com/Icex0/OpenFirebase/issues)

Automated Firebase security scanner that extracts Firebase configurations from APK files and performs unauthenticated and/or authenticated read and/or write scanning of common Firebase services (Realtime Database, Firestore, Storage, Remote Config), including support for all known service URL formats.

Supports multiple inputs including APK extraction via JADX decompilation, fast extract, single or multiple project IDs.

[>> See my blog for more information: https://ice0.blog/docs/openfirebase <<](https://ice0.blog/docs/openfirebase)

</div>


## Requirements

- Python 3.8+
- Java Runtime Environment (JRE) 8+ (required for JADX decompilation and apksigner tool)

## Installation

### Step 1: Install Java
Java is required for JADX decompilation (default mode) and apksigner.

#### macOS
```bash
# Using Homebrew (recommended)
brew install openjdk
```

#### Linux (Ubuntu/Debian)
```bash
# Using package manager
sudo apt update
sudo apt install default-jre
```

#### Windows
```bash
# Using Chocolatey (if installed)
choco install openjdk

# Or download and install from:
# https://www.oracle.com/java/technologies/downloads/
```

**Verify Java installation:**
```bash
java -version
```

### Step 2: Install OpenFirebase

#### Recommended: Using pipx

```bash
# Install pipx if you don't have it
python -m pip install --user pipx
python -m pipx ensurepath

# Install by cloning the repository
git clone https://github.com/Icex0/OpenFirebase.git
cd OpenFirebase
pipx install .
```

#### Default Wordlists and Payloads

OpenFirebase includes built-in wordlists and payloads in the repository. These files must be explicitly specified in command line arguments:
- Use `--fuzz-collections openfirebase/wordlist/firestore-collections.txt` for collection fuzzing
- Use `--write-rtdb-file openfirebase/payloads/openfirebase.json` for RTDB write testing
- Use `--write-storage-file openfirebase/payloads/openfirebase_storage_write_check.txt` for storage write testing

## How it works

<details>
<summary><strong>JADX Decompilation (Default)</strong></summary>

OpenFirebase uses JADX decompilation by default for source code analysis. This *Decompiling APK with JADX* phase can take a while, depending on the APK and your system (especially on VMs with limited resources):

- **Automatic Installation**: If JADX is not found, OpenFirebase will automatically download and install JADX.
- **Fast Alternative**: Use `--fast-extract` to skip JADX decompilation and only parse strings.xml for faster processing
1. **androguard Parsing**: Uses androguard to extract `/res/values/strings.xml` only
2. **String Analysis**: Searches for Firebase patterns in XML strings
3. **Quick Results**: Outputs Firebase URLs and basic configuration found in strings.xml
4. **Limited Scope**: Does not detect Firestore collections or patterns in Java source code

- **Why use JADX?**: JADX decompilation provides deeper analysis by searching through actual source code, detecting Firestore collections, and finding additional Firebase patterns that strings.xml-only analysis would miss
- JADX processing has a 30 minute timeout to prevent hanging (change in config.py). Note: In some cases the JADX process is not killed after 30 minutes and the extraction phase will not complete. Manually kill the correct JADX process that hangs and it will finish the extraction phase (I will fix this!) 
- Files are processed in order of size (smallest first) so it will take more time towards the end

</details>

<details>
<summary><strong>Firebase Database Scanning</strong></summary>

When using the `--read-rtdb` or `--write-rtdb` options, the script will scan all unique Firebase project IDs to check database accessibility and security status. The scanner:

- Tests standard Firebase Realtime Database URLs:
  - `https://PROJECT_ID.firebaseio.com/.json`
  - `https://PROJECT_ID-default-rtdb.firebaseio.com/.json`
- Handles region redirects automatically (e.g., europe-west1)
- **Read Testing (`--read-rtdb`)**: Evaluates response status codes:
  - **200**: Public database access
  - **403**: Permission denied (Protected)
  - **404**: Database not found
  - **423**: Database locked/deactivated
- **Write Testing (`--write-rtdb`)**: Attempts to write JSON data from specified file to test write permissions
- **Open-only files**: Automatically creates `*_database_open_only.txt` files when public databases are found

</details>

<details>
<summary><strong>Firebase Storage Scanning</strong></summary>

When using the `--read-storage` or `--write-storage` options, the script will scan all unique Firebase project IDs to check storage bucket accessibility:

- Tests Firebase Storage bucket URLs:
  - `https://firebasestorage.googleapis.com/v0/b/PROJECT_ID.appspot.com/o`
  - `https://firebasestorage.googleapis.com/v0/b/PROJECT_ID.firebasestorage.app/o`
- **Read Testing (`--read-storage`)**: Evaluates response status codes:
  - **200**: Public storage access.
  - **400**: Storage rules version 1 - listing disallowed.
  - **403**: Permission denied.
  - **412**: Service account missing permissions.
  - **404**: Storage bucket not found.
- **Write Testing (`--write-storage`)**: Attempts to upload specified file to test write permissions
- **Open-only files**: Automatically creates `*_storage_open_only.txt` files when public storage buckets are found

</details>

<details>
<summary><strong>Firebase Firestore Scanning</strong></summary>

When using the `--read-firestore` or `--write-firestore` options, the script will scan Firestore databases to check accessibility:

- **Extracted Collections**: Uses Firestore collection and document names found during JADX decompilation from each APK's source code
- **Default Collections**: When no collections are found, tests common collection names: `users`, `posts`, `messages`, `products`, `orders`
- **Collection Fuzzing**: When `--fuzz-collections` is used with a wordlist path and a public database is found, automatically fuzzes collection names
- Tests Firestore REST API endpoints:
  - `https://firestore.googleapis.com/v1/projects/PROJECT_ID/databases/(default)/documents/COLLECTION_NAME`
- **Read Testing (`--read-firestore`)**: Evaluates response status codes:
  - **200**: Public Firestore collection with data.
  - **200 (empty)**: Public database but collection doesn't exist.
  - **403**: Permission denied.
  - **404**: Database not found.
- **Write Testing (`--write-firestore`)**: Attempts to write specified string value to test document creation permissions
- **Open-only files**: Automatically creates `*_firestore_open_only.txt` files when public Firestore databases are found

</details>

<details>
<summary><strong>Firebase Remote Config Scanning</strong></summary>

When using the `--read-config` option, the script will scan Firebase Remote Config accessibility using extracted Google API keys and App IDs. The scanner:

- Extracts Google API keys and App IDs from `/res/values/strings.xml`
- Tests Firebase Remote Config API endpoints:
  - `https://firebaseremoteconfig.googleapis.com/v1/projects/{PROJECT_ID}/namespaces/firebase:fetch?key={API_KEY}`
- Makes POST requests with extracted App IDs
- Evaluates response status codes:
  - **200**: Remote Config accessible.
  - **401/403**: Permission denied. There might be other Google API restrictions.
  - **404**: Remote Config not found.
- **Open-only files**: Automatically creates `*_config_open_only.txt` files when accessible configs are found

</details>

<details>
<summary><strong>Resume from Previous Results</strong></summary>

When you have already run extraction and want to skip the extraction phase (JADX decompilation) entirely, you can use:

- `--resume`: Resume from an existing results directory containing a `*_firebase_items.txt` file and go directly to scanning
- `--resume-auth-file`: Resume using previously saved authentication data from `auth_data.json` file in the results directory, skipping the trial-and-error authentication process

</details>

<details>
<summary><strong>Direct Project ID Scanning</strong></summary>

When you already have extracted Firebase project IDs and want to skip the extraction phase, you can use:

- `--project-id`: Scan specific project IDs provided as comma-separated values
- `--project-id-file`: Scan project IDs from a file (one ID per line)

These options are particularly useful when:
- You've already run extraction and have a list of project IDs
- You have project IDs from other sources such as web

</details>

## Command Line Arguments

### Input Options
| Argument | Short | Description |
|----------|-------|-------------|
| `--file` | `-f` | Single APK file to process with JADX decompilation |
| `--apk-dir` | `-d` | JADX decompilation on directory containing APK files (*.apk). Recommended for multiple APKs |
| `--fast-extract` | `-F` | Use fast extraction (strings.xml only) instead of full source analysis. Faster but limited |
| `--resume` | `-r` | Resume from existing results folder containing *_firebase_items.txt file |
| `--exclude-project-id` | | Exclude specific project ID(s) when resuming (comma-separated for multiple IDs, can only be used with --resume) |
| `--project-id` | `-pi` | Scan specific Firebase project ID(s) without extraction (comma-separated for multiple IDs) |
| `--project-id-file` | `-pif` | Scan Firebase project IDs from a file (one ID per line) without extraction |
| `--parse-dns-file` | `-pdf` | Parse DNS entries from file and extract Firebase project IDs (outputs IDs without scanning) |

### Read Testing
| Argument | Short | Description |
|----------|-------|-------------|
| `--read-rtdb` | `-rr` | Test Firebase realtime database for unauthorized read access |
| `--read-storage` | `-rs` | Test Firebase storage buckets for unauthorized read access |
| `--read-config` | `-rc` | Test Firebase Remote Config for read access |
| `--read-firestore` | `-rf` | Test Firestore databases for unauthorized read access |
| `--collection-name` | | Collection name(s) to test with --read-firestore (comma-separated for multiple, defaults to 'users') |
| `--read-all` | `-ra` | Read Firebase databases, storage buckets, Remote Config, and Firestore for unauthorized access |
| `--scan-rate` | `-l` | Rate limit for scanning (requests per second) |
| `--fuzz-collections` | | Path to wordlist file for Firestore collection fuzzing when a publicly accessible database is found |

### Write Testing
| Argument | Short | Description |
|----------|-------|-------------|
| `--write-storage` | `-ws` | Test write access to Firebase storage buckets (requires --write-storage-file) |
| `--write-storage-file` | | Path to file to upload when testing storage write access (required with --write-storage) |
| `--write-firestore` | `-wf` | Test write access to Firestore databases (requires --write-firestore-value) |
| `--write-firestore-value` | | String value to write when testing Firestore write access (required with --write-firestore) |
| `--write-rtdb` | `-wr` | Test write access to Firebase Realtime Database (requires --write-rtdb-file with JSON data) |
| `--write-rtdb-file` | | Path to JSON file containing data to write when testing RTDB write access (required with --write-rtdb) |
| `--write-all` | `-wa` | Test write access to Firebase storage buckets, Firestore databases, and Realtime Database (requires --write-storage-file, --write-rtdb-file, and --write-firestore-value) |

### Processing Options
| Argument | Short | Description |
|----------|-------|-------------|
| `--output-dir` | `-o` | Output directory for all generated files (default: results/) |
| `--processes` | `-j` | Number of processes for concurrent APK processing (default: min(5, CPU count), max: 5) |
| `--proxy` | `-x` | Proxy for HTTP requests (format: protocol://host:port, e.g., http://127.0.0.1:8080) |

### Remote Config Credentials
| Argument | Short | Description |
|----------|-------|-------------|
| `--app-id` | `-i` | Google App ID for Remote Config scanning with --project-id or --project-id-file |
| `--api-key` | `-k` | Firebase API key for Remote Config scanning with --project-id or --project-id-file |
| `--cert-sha1` | | Android app certificate SHA-1 hash for Remote Config scanning (extracted from APK if not provided) |
| `--package-name` | | Android app package name for Remote Config scanning (extracted from APK if not provided) |

### Authentication
| Argument | Short | Description |
|----------|-------|-------------|
| `--check-with-auth` | `-C` | For read and write checks returning 401/403, retry with Firebase authentication |
| `--email` | `-e` | Email address for Firebase authentication (required with --check-with-auth) |
| `--password` | `-p` | Password for Firebase authentication (required with --check-with-auth) |
| `--resume-auth-file` | | Path to auth_data.json file or results directory containing saved authentication data for direct authentication (skips trial-and-error auth process) |


## Examples

I recommend scanning using --proxy http://127.0.0.1:8080 and Burp Suite with the JWT extension that highlights requests containing JWT tokens. This is especially useful during authenticated scanning, as it makes it easy to identify which requests succeeded. You can then easily test them and export requests as cURL commands, making them easy to reproduce in your PoC.

#### Only extract single file
```bash
# Only extract using JADX (default)
openfirebase -f file.apk
```

#### Only extract APKs using fast extract 
```bash
# Extract using APK directory with fast mode
openfirebase -d path/to/apks -F
```

#### Full unauthenticated read and write scan
```bash
# Extract, scan all services, test read and write access
openfirebase -d /path/to/apks --read-all --write-all --write-storage-file ./openfirebase/payloads/openfirebase_storage_write_check.txt --write-rtdb-file ./openfirebase/payloads/openfirebase.json --write-firestore-value "unauth_write_check_by_Icex0" --fuzz-collections ./openfirebase/wordlists/firestore-collections.txt
```

#### Full authenticated read and write scan
```bash
# Extract, scan all services, test read and write access with authentication
openfirebase -d /path/to/apks --read-all --write-all --write-storage-file ./openfirebase/payloads/openfirebase_storage_write_check.txt --write-rtdb-file ./openfirebase/payloads/openfirebase.json --write-firestore-value "unauth_write_check_by_Icex0" --check-with-auth --email pentester@company.com --password SecurePass123 --fuzz-collections ./openfirebase/wordlists/firestore-collections.txt
```

#### Resume from extraction only results and perform scans
```bash
# Resume from extraction only firebase items
openfirebase --resume ./2025-08-31_20-30-00_results --exclude-project-id "abc-project" --read-all
```

#### Full read scan using project ID (cert and package name are optional but needed if there are Google API restrictions)
```bash
openfirebase --project-id openfirebase --read-all --check-with-auth --email pentester@company.com --password SecurePass123 --api-key AIz... --cert-sha1 1126abfb2cc0656875e50099d1bb5376276ae5a5 --package-name com.openfire.base --proxy http://127.0.0.1:8080 
```

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

This tool is not affiliated with, endorsed by, or associated with Google LLC. This is an independent security research tool designed for legitimate security testing purposes. Use of this tool is at your own risk. Users are responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction.