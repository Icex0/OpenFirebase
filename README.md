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

Automated Firebase security scanner that extracts Firebase configurations from Android APKs and iOS IPAs and performs unauthenticated and/or authenticated read and/or write scanning of common Firebase services (Realtime Database, Firestore, Storage, Remote Config), including support for all known service URL formats. Detects accidentally embedded service account credentials for admin-level access that bypasses security rules.

Supports multiple inputs including Android APK extraction (DEX string pool + resources), iOS IPA extraction via GoogleService-Info.plist and Mach-O string scanning, and single or multiple project IDs. This means you can also use this tool if you find Firebase data in web applications.

> [>> See my blog for more information: https://ice0.blog/docs/openfirebase <<](https://ice0.blog/docs/openfirebase)

**See also:**
- [FireSA](https://github.com/Icex0/FireSA) — Service account exploitation tool for quickly demonstrating impact with a leaked private key.
- [Firebase Pentest Checklist](https://github.com/Icex0/firebase-pentest-checklist) — Complete Firebase pentesting checklist, including the OpenFirebase commands. Most of it can be done with this tool.

</div>


## Requirements

- Python 3.8+
- Java 11+ (required for the apksigner tool)

## Installation

### Step 1: Install Java
Java is required for apksigner (used to extract APK signing certificates).

#### macOS
```bash
# Using Homebrew (recommended)
brew install openjdk
echo 'export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
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

OpenFirebase includes a built-in firestore collection wordlist and example payloads for write testing. These files must be explicitly specified in command line arguments. Feel free to use your own:
- Use `--fuzz-collections openfirebase/wordlist/firestore-collections.txt` for collection fuzzing
- Use `--write-rtdb openfirebase/payloads/openfirebase.json` for RTDB write testing
- Use `--write-storage openfirebase/payloads/openfirebase_storage_write_check.txt` for storage write testing
- Use `--write-firestore "unauth_write_check"` for Firestore write testing (writes to `firestore_unauthenticated_access` collection)

<details>
<summary><strong>Firestore Collection Wordlist</strong> (<code>openfirebase/wordlist/firestore-collections.txt</code>)</summary>

```
account
accounts
activity
activities
address
addresses
admin
admins
analytics
app
app_config
app_settings
audit
auth
banner
banners
billing
bookmark
bookmarks
campaign
campaigns
cart
carts
category
categories
channel
channels
chat
chats
client
clients
comment
comments
config
configs
contact
contacts
conversation
conversations
coupon
coupons
credentials
customer
customers
data
db
delivery
deliveries
device
devices
discount
discounts
docs
document
documents
driver
drivers
email
emails
event
events
favorite
favorites
feed
feeds
feedback
file
files
follower
followers
friend
friends
groups
history
image
images
info
inventory
invoice
invoices
item
items
job
jobs
kyc
lead
leads
list
lists
location
locations
log
logs
login
logins
media
member
members
merchant
merchants
message
messages
meta
metadata
note
notes
notification
notifications
offer
offers
order
orders
organization
organizations
password
passwords
payment
payments
payout
payouts
people
permissions
person
photo
photos
plan
plans
post
posts
preferences
private
product
products
profile
profiles
project
projects
promo
promos
public
purchase
purchases
rating
ratings
record
records
referral
referrals
report
reports
request
requests
resource
resources
review
reviews
reward
rewards
role
roles
room
rooms
sale
sales
schedule
schedules
search
secret
secrets
seller
sellers
service
services
session
sessions
setting
settings
shipping
shop
shops
status
store
stores
story
stories
subscription
subscriptions
support
survey
surveys
tag
tags
task
tasks
team
teams
template
templates
thread
threads
ticket
tickets
token
tokens
tracking
transaction
transactions
transfer
transfers
trip
trips
upload
uploads
user
users
userdata
userinfo
vendor
vendors
video
videos
visitor
visitors
voucher
vouchers
wallet
wallets
wishlist
wishlists
```

</details>

<details>
<summary><strong>RTDB Write Payload</strong> (<code>openfirebase/payloads/openfirebase.json</code>)</summary>

```json
{"unauth_access":"OpenFirebase_write_check"}
```

</details>

<details>
<summary><strong>Storage Write Payload</strong> (<code>openfirebase/payloads/openfirebase_storage_write_check.txt</code>)</summary>

```
OpenFirebase - Unauth Firebase write access found
```

</details>

## How it works

<details>
<summary><strong>Android APK Extraction (DEX string pool + resources)</strong></summary>

OpenFirebase extracts Firebase items from Android APKs *without* spawning JADX. The path combines four sources into a single regex pass:

1. **`resources.arsc` strings** — every value in `strings.xml` across all `/res/values-*` locales (read via androguard, no decompile).
2. **DEX string pool** — every literal in every `classes*.dex`, pulled directly from the `string_ids` table via `androguard.core.dex.DEX.get_strings()`. This is where Java/Kotlin string literals live: Firebase URLs, `AIza...` API keys, Firestore collection names, `gserviceaccount.com` emails, and full `-----BEGIN PRIVATE KEY-----` blocks pasted into source.
3. **DEX bytecode walk** — `invoke-*` opcodes targeting `FirebaseFirestore.collection(...)` / `CollectionReference.document(...)` are paired with the most recent `const-string` in the same method to recover Firestore collection names that the bare string-pool walk can't label (the call site and the literal live in separate DEX tables).
4. **`assets/` and `res/raw/` text files** — `*.json`, `*.xml`, `*.txt`, `*.properties`, `*.cfg`, `*.conf`, `*.js`, `*.html` are read straight from the zip and fed through the same regex pipeline. Catches Firebase config blobs that ship as resource files (including Capacitor/Cordova hybrid apps that embed config in `assets/public/*.js`).

**Hardcoded service-account recovery.** PEM private-key blocks found in the DEX pool are paired with a `gserviceaccount.com` email if both appear exactly once in the same DEX file (otherwise the PEM is emitted as a standalone `Hardcoded_Private_Key` finding). Service-account JSON files bundled in `assets/` or `res/raw/` are still parsed independently with the existing walker.

**Known limitations.** Strings encrypted by DexGuard / Allatori / paid R8 plugins, runtime-built strings via `StringBuilder` / `String.format`, and strings embedded in native `lib/*.so` libraries are not recovered.

Files are processed in order of size (smallest first).

</details>

<details>
<summary><strong>iOS IPA Extraction</strong></summary>

OpenFirebase supports iOS `.ipa` bundles alongside Android APKs. Pass an `.ipa` to `-f` or mix `.apk` and `.ipa` files in a `-d` directory — extraction is dispatched per file based on extension.

- **Plist parsing.** Any file matching `GoogleService-Info*.plist` anywhere inside the app bundle is parsed. iOS keys (`API_KEY`, `PROJECT_ID`, `DATABASE_URL`, `STORAGE_BUCKET`, `GOOGLE_APP_ID`, `BUNDLE_ID`, ...) are mapped to canonical names so the same Firebase regex patterns match unchanged. Fully bespoke filenames (e.g. `GSI-Production.plist`) are not detected.
- **Service account JSON detection.** Every `.json` inside `Payload/<App>.app/` is parsed and kept if it contains `"type": "service_account"` with a valid `client_email` and `private_key`.
- **Mach-O binary string scanning.** The main app executable is scanned for printable ASCII strings, which are then run through the same `firebase_rules.json` regex patterns used by the plist/APK paths — catching API keys, project IDs, App IDs, database URLs, storage buckets, Firestore collection names, and any other pattern defined in the rules file.
- **Hardcoded PEM private key recovery.** Full `-----BEGIN PRIVATE KEY-----` blocks are extracted from the binary and surfaced as a `Hardcoded_Private_Key` finding. These are reported standalone for manual investigation (the matching `client_email` cannot be recovered from the binary alone).
- **Bundle identifier.** `CFBundleIdentifier` is read from `Info.plist` and emitted as `IPA_Bundle_ID`. It's used by `--ios-bundle-id` to bypass iOS API key restrictions on Identity Toolkit and Remote Config requests.
- **No Firestore collection detection on iOS.** Unlike Android's DEX walk, the Mach-O does not preserve the call-site association between `collectionWithPath:` and its string argument, so collection names aren't labeled automatically.

</details>

<details>
<summary><strong>Firebase Realtime Database Scanning</strong></summary>

When using the `--read-rtdb` or `--write-rtdb` options, the script will scan all unique Firebase project IDs to check database accessibility and security status. The scanner:

- Tests standard Firebase Realtime Database URLs:
  - `https://PROJECT_ID.firebaseio.com/.json`
  - `https://PROJECT_ID-default-rtdb.firebaseio.com/.json`
- Handles region redirects automatically (e.g., europe-west1)
- Supports multiple Realtime Databases in the same project. The second database automatically has the same name as the project, if not manually changed.
- **Read Testing (`--read-rtdb`)**: Evaluates response status codes:
  - **200**: Public database access
  - **403**: Permission denied (Protected)
  - **404**: Database not found
  - **423**: Database locked/deactivated
- **Write Testing (`--write-rtdb`)**: Attempts to write JSON data from specified file to test write permissions
- **Open-only files**: Automatically creates `*_database_open_only.txt` files when public databases are found
- **Authentication tokens**: Firebase ID tokens are sent as `?auth=<token>` and service account OAuth2 tokens as `?access_token=<token>`. Service account tokens require the `firebase.database` scope, which OpenFirebase requests automatically.

</details>

<details>
<summary><strong>Firebase Storage Scanning</strong></summary>

When using the `--read-storage` or `--write-storage` options, the script will scan all unique Firebase project IDs to check storage bucket accessibility:

- Tests both the Firebase Storage REST API and the underlying Google Cloud Storage JSON API for each bucket suffix. The two surfaces are governed by different access systems (Firebase Storage Rules vs GCS IAM), so a bucket can be public on one and locked on the other:
  - `https://firebasestorage.googleapis.com/v0/b/PROJECT_ID.appspot.com/o`
  - `https://firebasestorage.googleapis.com/v0/b/PROJECT_ID.firebasestorage.app/o`
  - `https://storage.googleapis.com/storage/v1/b/PROJECT_ID.appspot.com/o`
  - `https://storage.googleapis.com/storage/v1/b/PROJECT_ID.firebasestorage.app/o`
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

When using the `--read-firestore` or `--write-firestore` options, the script will scan Firestore (default) databases to check accessibility:

- **Extracted Collections**: Uses Firestore collection names recovered from each APK's DEX bytecode walk
- **Collection Fuzzing**: When `--fuzz-collections` is used with a wordlist path and a public Firestore database is found, automatically fuzzes common collection names: `users`, `posts`, `messages`, `products`, `orders` etc
- Uses Firestore REST API endpoint:
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

- Extracts Google API keys and App IDs from string resources across all `/res/values-*` directories
- Uses Firebase Remote Config API:
  - `https://firebaseremoteconfig.googleapis.com/v1/projects/{PROJECT_ID}/namespaces/firebase:fetch?key={API_KEY}`
- Evaluates response status codes:
  - **200**: Remote Config accessible.
  - **401/403**: Permission denied. There might be other Google API restrictions.
  - **404**: Remote Config not found.
- **Open-only files**: Automatically creates `*_config_open_only.txt` files when accessible configs are found

</details>

<details>
<summary><strong>Authenticated Scanning and Google API Restriction Bypass</strong></summary>

When using the `--check-with-auth` option, OpenFirebase attempts to authenticate with Firebase services to access protected resources that return 401/403 errors during unauthenticated scanning:

- **Account Creation and sign-in**: Automatically attempts to create Firebase user accounts using the Identity Toolkit API with extracted API keys and fetch access token.
- **Anonymous sign-in**: If account creation with email/password fails, automatically retries with anonymous sign-in.
- **Google OAuth sign-in**: If email/password auth is disabled (`OPERATION_NOT_ALLOWED`), falls back to Google OAuth via `signInWithIdp` when `--google-id-token` is provided. Can also be used standalone without email/password. See [Google OAuth Authentication](#google-oauth-authentication).
- **API Key Restriction Bypass**: Bypasses client-side Google API key restrictions by setting the matching headers — `--cert-sha1` + `--package-name` (Android, auto-extracted from APK), `--ios-bundle-id` (iOS), and `--referer` (HTTP referrer). Only IP-address restrictions provide real protection. These bypasses apply to Identity Toolkit (auth) and Remote Config requests, since those are the only Firebase APIs that authenticate via `?key=AIza...` and are therefore subject to API key restrictions.
- **Multi-Key Testing**: Tests multiple extracted API keys and certificate combinations to find working authentication methods
- **Authenticated Retry**: Retries previously failed read/write operations using obtained authentication token
- **Authentication Persistence**: Saves successful authentication data to `auth_data.json` for future `--resume-auth-file` usage

</details>

<details>
<summary><strong>Service Account Authentication</strong></summary>

OpenFirebase detects Firebase service account credentials (`client_email` + `private_key`) accidentally embedded in APK files. Service accounts with admin-level roles (e.g. `firebase-adminsdk`) bypass all Firebase security rules, granting unrestricted access.

#### Detection
- **JSON service account files**: Reads `assets/`, `res/raw/`, and root-level JSON files directly from the APK and parses any containing `"type": "service_account"` with `client_email` and `private_key` fields
- **Hardcoded PEM keys**: Scans the DEX string pool for `-----BEGIN PRIVATE KEY-----` blocks and `@*.gserviceaccount.com` emails, pairing them when both appear exactly once in the same DEX file

#### Authentication Flow
When credentials are found (or manually provided via `--service-account` and `--private-key`), OpenFirebase authenticates using the Google OAuth2 service-to-service JWT flow:
1. Signs a JWT with the service account's RSA private key
2. Exchanges it at `oauth2.googleapis.com/token` for a short-lived bearer token
3. Uses the bearer token for all RTDB, Firestore, and Storage scans — always in addition to the default unauthenticated request

Results using the service account token are labeled `PUBLIC_SA` to distinguish them from regular authenticated results (`PUBLIC_AUTH`).

#### What a Service Account Can Access
An admin-level service account doesn't just bypass security rules for read/write — it grants access to the full Firebase Admin SDK, including:
- **Realtime Database**: Read/write any path, regardless of security rules
- **Firestore**: Read/write any collection/document, regardless of security rules
- **Storage**: Read/write any file in any bucket, regardless of security rules
- **Firebase Auth Admin API**: List all user accounts, read user data (email, phone, display name, providers, MFA status, custom claims), create/delete users, generate custom auth tokens for user impersonation, and disable MFA

</details>

<details>
<summary><strong>Google OAuth Authentication</strong></summary>

Some Firebase projects have email/password authentication disabled but Google sign-in enabled. When OpenFirebase encounters `OPERATION_NOT_ALLOWED` during email/password auth, it can fall back to Google OAuth via `signInWithIdp` if a Google ID token is provided.

#### How to Obtain a Google ID Token

The token must come from the target app's own Google sign-in flow so that its `aud` claim matches the Firebase project's OAuth client ID.

1. **Set up an intercepting proxy** (Burp Suite, mitmproxy, etc.) and install its CA certificate on your device or emulator.
2. **Bypass SSL pinning** if the app enforces it (e.g. using Frida or objection).
3. **Open the target app** and tap "Sign in with Google".
4. **Complete the Google sign-in** with any Google account.
5. **In your proxy history**, find the request to `identitytoolkit.googleapis.com/v1/accounts:signInWithIdp`. The app makes this call after the Google sign-in completes.
6. **Copy the `id_token` value** from the `postBody` parameter in that request — it is a JWT starting with `eyJ...`.

#### Usage

```bash
# Standalone — Google OAuth only, no email/password needed
openfirebase -f app.apk -C --google-id-token "eyJhbGciOi..." --read-all

# Combined — tries email/password first, falls back to Google OAuth on OPERATION_NOT_ALLOWED
openfirebase -f app.apk -C -e test@test.com -p pass123 --google-id-token "eyJhbGciOi..." --read-all
```

Google ID tokens expire after approximately 1 hour, so capture a fresh token before scanning.

</details>

<details>
<summary><strong>Resume from Previous Results</strong></summary>

When you have already run extraction and want to skip the extraction phase entirely, you can use:

- `--resume`: Resume from an existing results directory containing a `*_firebase_items.txt` file and go directly to scanning
- `--resume-auth-file`: Resume using previously saved authentication data from `auth_data.json` file in the results directory, skipping the trial-and-error authentication process

</details>

<details>
<summary><strong>Direct Project ID Scanning</strong></summary>

When you already have extracted Firebase project IDs and want to skip the extraction phase or when you have project IDs from other sources such as web, you can use:

- `--project-id`: Scan specific project IDs provided as comma-separated values
- `--project-id-file`: Scan project IDs from a file (one ID per line)

</details>

## Command Line Arguments

### Input Options
| Argument | Short | Description |
|----------|-------|-------------|
| `--file` | `-f` | Single mobile bundle to process: `.apk` (Android: DEX string pool + resources) or `.ipa` (iOS: plist + Mach-O strings). |
| `--apk-dir` | `-d` | Directory containing mobile bundles (`*.apk` and/or `*.ipa`) |
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
| `--read-all` | `-ra` | Test Firebase databases, storage buckets, Remote Config, and Firestore for unauthorized access |
| `--scan-rate` | `-l` | Rate limit for scanning (requests per second) |
| `--fuzz-collections` | | Path to wordlist file for Firestore collection fuzzing when a publicly accessible database is found |

### Write Testing
| Argument | Short | Description |
|----------|-------|-------------|
| `--write-storage <file>` | `-ws` | Test write access to Firebase storage buckets (provide path to file to upload) |
| `--write-firestore <value>` | `-wf` | Test write access to Firestore databases (provide string value to write) |
| `--write-rtdb <file>` | `-wr` | Test write access to Firebase Realtime Database (provide path to JSON file with data to write) |
| `--write-all` | `-wa` | Test write access to Firebase storage, Firestore, and RTDB (requires --write-storage, --write-rtdb, and --write-firestore) |

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
| `--cert-sha1` | | Android app certificate SHA-1 hash to bypass Android-app API key restrictions (extracted from APK if not provided) |
| `--package-name` | | Android app package name to bypass Android-app API key restrictions (extracted from APK if not provided) |
| `--referer` | | Value for the `Referer` header to bypass website API key restrictions (e.g. `https://app.example.com/`) |
| `--ios-bundle-id` | | Value for `X-Ios-Bundle-Identifier` to bypass iOS-app API key restrictions |

### Authentication
| Argument | Short | Description |
|----------|-------|-------------|
| `--check-with-auth` | `-C` | For read and write checks returning 401/403, retry with Firebase authentication |
| `--email` | `-e` | Email address for Firebase authentication (required with --check-with-auth unless --google-id-token is used) |
| `--password` | `-p` | Password for Firebase authentication (required with --email) |
| `--google-id-token` | | Google OAuth ID token for signInWithIdp fallback when email/password auth is disabled (see [Google OAuth Authentication](#google-oauth-authentication)) |
| `--resume-auth-file` | | Path to auth_data.json file or results directory containing saved authentication data for direct authentication (skips trial-and-error auth process) |

### Service Account Authentication
| Argument | Description |
|----------|-------------|
| `--service-account` | Service account email (client_email) for admin-level authentication via Google OAuth2 JWT flow (bypasses security rules) |
| `--private-key` | Path to PEM private key file for service account authentication (required with --service-account). Also accepts inline key strings with `\n` escapes |


## Examples

I recommend scanning using --proxy http://127.0.0.1:8080 and Burp Suite with the JWT extension that highlights requests containing JWT tokens. This is especially useful during authenticated scanning, as it makes it easy to identify which requests succeeded. You can then easily test them and export requests as cURL commands, making them easy to reproduce in your PoC.

#### Only extract single file
```bash
openfirebase -f file.apk
```

#### Only extract a directory of APKs/IPAs
```bash
openfirebase -d path/to/apks
```

#### Full unauthenticated read and write scan
```bash
# Extract, scan all services, test read and write access
openfirebase -d /path/to/apks --read-all --write-all --write-storage ./openfirebase/payloads/openfirebase_storage_write_check.txt --write-rtdb ./openfirebase/payloads/openfirebase.json --write-firestore "unauth_write_check_by_Icex0" --fuzz-collections ./openfirebase/wordlist/firestore-collections.txt
```

#### Full authenticated read and write scan
```bash
# Extract, scan all services, test read and write access with authentication
openfirebase -d /path/to/apks --read-all --write-all --write-storage ./openfirebase/payloads/openfirebase_storage_write_check.txt --write-rtdb ./openfirebase/payloads/openfirebase.json --write-firestore "unauth_write_check_by_Icex0" --check-with-auth --email pentester@company.com --password SecurePass123 --fuzz-collections ./openfirebase/wordlist/firestore-collections.txt
```

#### Resume from extraction only results and perform all read scans
```bash
# Resume from extraction only firebase items
openfirebase --resume ./2025-08-31_20-30-00_results --exclude-project-id "abc-project" --read-all
```

#### Full read scan using project ID (cert-sha1 and package name are optional but needed if there are Google API restrictions)
```bash
openfirebase --project-id openfirebase --read-all --check-with-auth --email pentester@company.com --password SecurePass123 --api-key AIz... --app-id 1:482910573864:android:ab12cd34ef56gh78ij90kl --cert-sha1 1126abfb2cc0656875e50099d1bb5376276ae5a5 --package-name com.openfire.base --proxy http://127.0.0.1:8080 
```

#### Scan with service account credentials from a JSON key file
```bash
openfirebase --project-id my-project --service-account firebase-adminsdk-xxxxx@my-project.iam.gserviceaccount.com --private-key /path/to/serviceAccountKey.pem --read-all
```

#### Extract APK and automatically use any found service account credentials
```bash
# If a service account is found during extraction, it will be used automatically for scanning
openfirebase -f app.apk --read-all
```

#### Authenticated scan using Google OAuth (for projects with email/password auth disabled)
```bash
# Capture the Google ID token from the app's sign-in flow via intercepting proxy, then:
openfirebase -f app.apk -C --google-id-token "eyJhbGciOi..." --read-all
```

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

This tool is not affiliated with, endorsed by, or associated with Google LLC. This is an independent security research tool designed for legitimate security testing purposes. Use of this tool is at your own risk. Users are responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction.
