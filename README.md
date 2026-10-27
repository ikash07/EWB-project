# EWB Phishing URL Awareness Checker

## Overview
Phishing is a social engineering cyberattack where fraudulent links or messages trick individuals into exposing sensitive data such as credentials, financial tokens, or personal identifiers. The **EWB Phishing URL Awareness Checker** is a lightweight, defensive security tool that inspects the raw text of a URL for observable warning indicators. Operating purely as an offline text analyzer, it flags suspicious URL characteristics without opening or communicating with the web address.

## Features
- Detects an `@` symbol in the URL (browsers navigate to the domain after the `@`, ignoring text preceding it).
- Flags unusually long URLs (over 100 characters) commonly used to push misleading paths or hide destinations.
- Flags IP-address hostnames (bare numbers frequently indicate rogue servers bypassing domain reputation checks).
- Flags excessive hostname segments (5 or more parts/subdomains used to simulate legitimate structures).
- Flags punycode-style hostnames (`xn--`) which can disguise look-alike Internationalized Domain Name (IDN) homograph attacks.
- Flags the unencrypted `HTTP` scheme where transmissions can be intercepted or manipulated in transit.
- **Interactive Multi-URL Evaluation Loop** (Improvement A): Continuous command-line evaluation with a dedicated quit command (`q`).
- **Quantified Warning Summary** (Improvement B): Highlights review severity when warning indicators are detected (`REVIEW CAREFULLY: X warning sign(s) found.`).
- **Resilient Exception Handling** (Improvement C): Shields against malformed inputs (e.g., incomplete IPv6 brackets) to ensure zero crashes.

## Requirements
Python 3.10 or later. No extra packages needed (uses Python standard library exclusively).

## How to Run
- **Windows:**
  ```powershell
  python phishing_checker.py
  ```
- **Mac/Linux:**
  ```bash
  python3 phishing_checker.py
  ```

## Example Output
```text
EWB Phishing URL Awareness Checker
Text checks only - this program does not open URLs.

Enter a sample URL (or type q to quit): http://192.0.2.10/account

Result:
- Uses an IP address instead of a familiar domain.
- Uses HTTP. HTTPS alone does not prove trust.

REVIEW CAREFULLY: 2 warning sign(s) found.

Never enter passwords from unexpected links.

Enter a sample URL (or type q to quit): q
Goodbye! Stay alert online.
```

## Testing
| # | Input | Expected | Actual | Result |
|---|-------|----------|--------|--------|
| 1 | `https://www.example.com/login` | No warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | `http://192.0.2.10/account` | Flags IP-address hostname and HTTP | Uses an IP address instead of a familiar domain. / Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 3 | `http://example.com@sample.invalid/login` | Flags @ symbol and HTTP | Contains an @ symbol; inspect carefully. / Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Flags many hostname segments | Contains many hostname segments/subdomains. | PASS |
| 5 | `https://xn--example.invalid/` | Flags punycode-style hostname | Contains a punycode-style hostname. | PASS |

> Complete test run notes and environment metadata are documented in [tests/test_samples.md](tests/test_samples.md).

## Screenshots
![Sample run](screenshots/sample_run.png)
![Test results](screenshots/test_results.png)

## Improvements
1. **Interactive CLI Loop with Exit Support (Option A)**:
   - *What changed:* Replaced single-run execution with a `while True` evaluation loop that supports exit commands (`q`, `quit`, `exit`).
   - *Why:* Enables users and security analysts to inspect multiple URLs sequentially without needing to restart the Python process every time.
   - *How tested:* Ran a sequential test session with all test cases back-to-back, entered `q`, and verified that the program cleanly terminated with a safety reminder.

2. **Distinct Warning Summary Banner (Option B)**:
   - *What changed:* Introduced a `has_warnings()` helper filter that detects actual security flags versus benign informational status messages, outputting a bold `REVIEW CAREFULLY: X warning sign(s) found.` count.
   - *Why:* Provides instant cognitive clarity and quantifies risk exposure for the user.
   - *How tested:* Validated that benign URLs (which yield informational status) do not trigger the alert, whereas flagged samples display accurate warning counts.

3. **Exception-Safe URL Parsing (Option C)**:
   - *What changed:* Wrapped `urlparse(candidate)` in a `try...except ValueError` construct returning `"This text is not a valid URL format."`.
   - *Why:* Prevents unhandled runtime crashes when processing malformed inputs such as incomplete IPv6 literals (`http://[bad`).
   - *How tested:* Fed `http://[bad` into the checker; confirmed that the application caught the syntax failure safely and reported the formatted error without terminating unexpectedly.

## Limitations
This is strictly an educational awareness tool. It only inspects visible URL text strings using static heuristic checks. It does not visit websites, execute network queries, scan server binaries for malware, or consult threat intelligence reputation feeds. A result of **"No listed warning signs found" does NOT mean a URL is safe**, as sophisticated adversaries can craft clean-looking URLs on newly registered or compromised domains.

## Ethical Use
Use sample strings and documentation addresses only. Do not harvest credentials, create deceptive links, or attempt unauthorized testing against external web services. This project is intended solely for defensive cybersecurity training and educational awareness.

## Author
Student Developer, Cybersecurity Mini Project, EWB Courses
