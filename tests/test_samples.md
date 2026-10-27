# Test Results

Python version used: 3.13.6 | Operating system: Windows 11 | Date: 2026-10-27

| # | Input | Expected result | Actual result | Pass/Fail |
|---|-------|-----------------|---------------|-----------|
| 1 | https://www.example.com/login | No listed warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | http://192.0.2.10/account | IP address + HTTP | Uses an IP address instead of a familiar domain. / Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 3 | http://example.com@sample.invalid/login | @ symbol + HTTP | Contains an @ symbol; inspect carefully. / Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 4 | https://a.b.c.d.e.example.invalid/path | Many hostname segments | Contains many hostname segments/subdomains. | PASS |
| 5 | https://xn--example.invalid/ | Punycode-style hostname | Contains a punycode-style hostname. | PASS |

## Notes
- Testing demonstrated that benign-looking URLs can evade basic text heuristics, reinforcing that absence of warnings does not prove safety.
- The `@` sign in URLs poses a significant risk because browsers route to the domain after the symbol, ignoring preceding credentials/lookalikes.
- Punycode (`xn--`) represents internationalized domain names (IDN) which can easily be abused in homograph attacks to impersonate legitimate websites.
