![Alt text](https://github.com/glask1d/GoobQR/blob/main/images/GoobSecBanner.jpeg)


--------------------------------------------------

# GoobFuzz

**GoobFuzz** is a powerful, flexible web fuzzer designed for security testing, endpoint discovery, and API exploration. Built for penetration testers and security researchers, it supports customizable HTTP requests, wordlist transformations, multi-threaded fuzzing, and advanced response filtering. Whether you're testing a web application or brute-forcing API endpoints, GoobFuzz offers a robust set of features to streamline your workflow.

## Table of Contents
- [Features](#features)
- [Setup & Installation](#installation)
- [Notes](#notes)


## Features

GoobFuzz includes 28 features to support a wide range of fuzzing scenarios. Each feature is described below with an example command to demonstrate its use.

### 1. Target URL Fuzzing (`-u/--url`)
Replace the `GOOB` placeholder in a URL with words from a wordlist to discover endpoints.
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst
```

### 2. Wordlist Support (-w/--wordlist)
Specify a wordlist file for fuzzing (required).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst
```

### 3. Concurrent Threads (-t/--threads)
Set the number of concurrent threads for faster fuzzing (default: 10).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -t 20
```

### 4. HTTP Method Selection (-m/--method)
Choose the HTTP method (e.g., GET, POST) for requests (ignored with --request-file).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -m POST
```

### 5. Filter Status Codes (-fc/--filter-code)
Exclude responses with specified status codes (comma-separated).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -fc 404
```

### 6. Filter Response Size (-fs/--filter-size)
Exclude responses with a specific content length (in bytes).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -fs 5
```

### 7. Output File (-o/--output)
Save results to a file.
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -o results.txt
```

### 8. Disable Colored Output (--no-color)
Disable colored console output for compatibility.
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst --no-color
```

### 9. Custom Headers (-H/--headers)
Add custom HTTP headers (repeatable).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -H "Authorization: Bearer token123"
```

### 10. Custom Cookies (-c/--cookies)
Add custom cookies (semicolon-separated).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -c "session=abc123;user=admin"
```

### 11. Follow Redirects (--follow-redirects)
Follow HTTP redirects in responses.
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst --follow-redirects
```

### 12. Proxy Support (-p/--proxy)
Route requests through a proxy (e.g., Burp Suite).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -p http://127.0.0.1:8080
```

### 13. Base64 Encoding (--base64)
Base64-encode each word before fuzzing.
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst --base64
```

### 14. Custom User-Agent (--user-agent)
Set a custom User-Agent (default: GoobFuzz v1.0).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst --user-agent "Mozilla/5.0"
```

### 15. Raw HTTP Request File (--request-file)
Use a raw HTTP request file with GOOB placeholders instead of -u/-m.
```bash
python3 GoobFuzz.py --request-file login.req -w wordlist.lst
```

### 16. Requests Per Second Limiting (--rps)
Limit requests per second to avoid overwhelming servers.
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst --rps 5
```

### 17. Wordlist Encoding (--encoding)
Specify wordlist file encoding (default: utf-8, falls back to latin-1).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst --encoding latin-1
```

### 18. File Extensions (-x/--extensions)
Append extensions (comma-separated) to each word.
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -x php,html
```

### 19. Verbose Mode (-v/--verbose)
Show all responses, including 404s (default: hide 404s).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -v
```

### 20. Response Body Regex Filtering (--match-regex)
Filter responses where the body matches a regex pattern.
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -x php --match-regex "Hello"
```

### 21. Request Timeout (--timeout)
Set a custom request timeout in seconds (default: 5.0).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst --timeout 2.0
```

### 22. Word Transformations (--transform)
Apply transformations (e.g., upper, lower, cap, append_<string>) to each word.
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst --transform upper,append_123
```

### 23. Randomized Word Order (--randomize)
Shuffle the wordlist to randomize request order.
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -v --randomize
```

### 24. Multiple GOOB Placeholders (--multi-goob)
Handle multiple GOOB placeholders (same: same word, combo: all combinations).
```bash
python3 GoobFuzz.py --request-file login.req -w wordlist.lst --multi-goob same
```

### 25. Response Header Filtering (--match-header)
Filter responses by HTTP header key-value pairs (repeatable).
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -x php --match-header "Content-Type:text/html"
```

### 26. Silent Mode (--silent)
Suppress non-result output (progress, warnings, ASCII art) for scripting.
```bash
python3 GoobFuzz.py -u http://127.0.0.1/GOOB -w wordlist.lst -x php --silent
```

### 27. SSL Verification Control (--ignore-ssl/--no-ignore-ssl)
Ignore SSL certificate verification (default) or enforce it.
```bash
python3 GoobFuzz.py -u https://127.0.0.1/GOOB -w wordlist.lst --no-ignore-ssl
```

----------------------------------------------------------------------------------------------------

## Installation
*NOTE* If you're using Kali Linux you may have to install on a python virtual environment. It's probably a good idea to do that anyways, but its optional.

### Setting up a python virtual environment
```bash
python3 -m venv /path/to/venv (ex: python3 -m venv /home/glask1d/myvenv)
```
#### Activate the environment
```bash
source /path/to/env/bin/activate
```

***(If you dont need a virtual environment you can skip the above steps)***

### Installing dependencies

```bash
pip3 install -r requirements.txt
```

***You should now be able to run the script***


## Notes

- Run into issues installing or running the tool?
- Found a bug?
- Have an idea for an additional feature?

Feel free to send me a DM on X(Twitter) or just tag me in a post. https://x.com/GLAsk1d

----------------------------------------------------------------------------------------------------


***Disclaimer: For Educational Purposes Only
GoobFuzz is a web fuzzing tool developed for educational purposes and ethical security research. It is intended to assist security professionals and researchers in testing and improving the security of systems and applications with explicit permission from the system owner. 
Unauthorized use of GoobFuzz to access, scan, or test systems without consent is strictly prohibited and may violate applicable laws. The developers and contributors of GoobFuzz assume no liability for any misuse or damage caused by the tool. By using GoobFuzz, you agree to use it responsibly, ethically, and in compliance with all relevant local, national, and international laws.***
