import argparse
import requests
import threading
from queue import Queue
from colorama import init, Fore, Style
import sys
import time
import urllib3
import base64
from urllib.parse import urlparse
import re
import random

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# ASCII art for welcome message
WELCOME_ASCII = """
  ▄████     ▒█████      ▒█████      ▄▄▄▄        █████▒    █    ██    ▒███████▒   ▒███████▒
 ██▒ ▀█▒   ▒██▒  ██▒   ▒██▒  ██▒   ▓█████▄    ▓██   ▒     ██  ▓██▒   ▒ ▒ ▒ ▄▀░   ▒ ▒ ▒ ▄▀░
▒██░▄▄▄░   ▒██░  ██▒   ▒██░  ██▒   ▒██▒ ▄██   ▒████ ░    ▓██  ▒██░   ░ ▒ ▄▀▒░    ░ ▒ ▄▀▒░ 
░▓█  ██▓   ▒██   ██░   ▒██   ██░   ▒██░█▀     ░▓█▒  ░    ▓▓█  ░██░     ▄▀▒   ░     ▄▀▒   ░
░▒▓███▀▒   ░ ████▓▒░   ░ ████▓▒░   ░▓█  ▀█▓   ░▒█░       ▒▒█████▓    ▒███████▒   ▒███████▒
 ░▒   ▒    ░ ▒░▒░▒░    ░ ▒░▒░▒░    ░▒▓███▀▒    ▒ ░       ░▒▓▒ ▒ ▒    ░▒▒ ▓░▒░▒   ░▒▒ ▓░▒░▒
  ░   ░      ░ ▒ ▒░      ░ ▒ ▒░    ▒░▒   ░     ░         ░░▒░ ░ ▔    ░░▒ ▒ ░ ▒   ░░▒ ▒ ░ ▒
░ ░   ░    ░ ░ ░ ▒     ░ ░ ░ ▒      ░    ░     ░ ░        ░░░ ░ ░    ░ ░ ░ ░ ░   ░ ░ ░ ░ ░
      ░        ░ ░         ░ ░      ░                       ░          ░ ░         ░ ░    
                                         ░                           ░           ▔        
"""

# Global variables for rate limiting
request_count = 0
last_reset_time = time.time()
rate_limit_lock = threading.Lock()

def display_welcome_message(no_color, silent):
    """Display the ASCII welcome message."""
    if silent:
        return
    if no_color:
        print(WELCOME_ASCII)
    else:
        colored_ascii = f"{Fore.GREEN}{WELCOME_ASCII}{Style.RESET_ALL}"
        print(colored_ascii)

def print_progress(completed, total, silent):
    """Print progress update."""
    if silent:
        return
    percentage = (completed / total) * 100
    print(f"{Fore.BLUE}[*] Progress: {completed}/{total} ({percentage:.2f}%)", end="\r")

def print_message(message, silent, color=Fore.BLUE):
    """Print message with optional color, respecting silent mode."""
    if silent:
        return
    print(f"{color}{message}{Style.RESET_ALL}")

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="A simple web fuzzer :DDD v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "-u", "--url",
        help="Target URL with GOOB keyword (e.g., http://example.com/GOOB) or base URL for scheme when using --request-file"
    )
    parser.add_argument(
        "-w", "--wordlist",
        required=True,
        help="Path to wordlist file"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )
    parser.add_argument(
        "-m", "--method",
        default="GET",
        help="HTTP method (default: GET, ignored with --request-file)"
    )
    parser.add_argument(
        "-fc", "--filter-code",
        help="Filter status codes (comma-separated, e.g., 404,500)"
    )
    parser.add_argument(
        "-fs", "--filter-size",
        type=int,
        help="Filter response size (in bytes)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file to save results"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    parser.add_argument(
        "-H", "--headers",
        action="append",
        help="Custom headers (e.g., 'User-Agent: Mozilla/5.0')"
    )
    parser.add_argument(
        "-c", "--cookies",
        help="Custom cookies (e.g., 'session=abc123; user=admin')"
    )
    parser.add_argument(
        "--follow-redirects",
        action="store_true",
        help="Follow HTTP redirects"
    )
    parser.add_argument(
        "-p", "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "--base64",
        action="store_true",
        help="Base64 encode each word before request"
    )
    parser.add_argument(
        "--user-agent",
        help="Custom User-Agent (e.g., 'Mozilla/5.0')"
    )
    parser.add_argument(
        "--request-file",
        help="Path to raw HTTP request file (e.g., request.txt)"
    )
    parser.add_argument(
        "--rps",
        type=float,
        help="Requests per second (e.g., 10 for 10 requests/sec)"
    )
    parser.add_argument(
        "--encoding",
        default="utf-8",
        help="Wordlist file encoding (e.g., 'utf-8', 'latin-1')"
    )
    parser.add_argument(
        "-x", "--extensions",
        help="Comma-separated list of extensions to append (e.g., 'php,txt,html')"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show all responses, including 404s"
    )
    parser.add_argument(
        "--match-regex",
        help="Show responses matching regex in body (e.g., 'Login successful')"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Request timeout in seconds (default: 5.0)"
    )
    parser.add_argument(
        "--transform",
        help="Transform words (e.g., 'upper,lower,cap,append_123')"
    )
    parser.add_argument(
        "--randomize",
        action="store_true",
        help="Randomize wordlist order"
    )
    parser.add_argument(
        "--multi-goob",
        choices=["same", "combo"],
        help="Handle multiple GOOB placeholders (same: use same word, combo: try all combinations)"
    )
    parser.add_argument(
        "--match-header",
        action="append",
        help="Filter responses by header (e.g., 'Content-Type:application/json')"
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Suppress non-result output (progress, warnings, ASCII art)"
    )
    
    # Mutually exclusive group for SSL verification
    ssl_group = parser.add_mutually_exclusive_group()
    ssl_group.add_argument(
        "--ignore-ssl",
        action="store_true",
        default=True,
        help="Ignore SSL certificate verification (default)"
    )
    ssl_group.add_argument(
        "--no-ignore-ssl",
        action="store_true",
        help="Verify SSL certificates"
    )
    
    args = parser.parse_args()
    
    # Validate that GOOB is in the URL when not using request file
    if not args.request_file and (not args.url or "GOOB" not in args.url):
        print_message("[!] Error: The URL must contain the GOOB keyword (e.g., http://example.com/GOOB) when --request-file is not used", args.silent, Fore.RED)
        sys.exit(1)
    
    # Validate RPS
    if args.rps is not None and args.rps <= 0:
        print_message("[!] Error: --rps must be a positive number", args.silent, Fore.RED)
        sys.exit(1)
    
    # Validate timeout
    if args.timeout <= 0:
        print_message("[!] Error: --timeout must be a positive number", args.silent, Fore.RED)
        sys.exit(1)
    
    # Validate and process extensions
    if args.extensions:
        extensions = [ext.strip().lstrip(".") for ext in args.extensions.split(",") if ext.strip()]
        if not extensions:
            print_message("[!] Error: --extensions must contain non-empty extensions (e.g., 'php,txt')", args.silent, Fore.RED)
            sys.exit(1)
        args.extensions = extensions
    else:
        args.extensions = []
    
    # Validate regex
    if args.match_regex:
        try:
            re.compile(args.match_regex)
        except re.error:
            print_message(f"[!] Error: Invalid regex pattern: {args.match_regex}", args.silent, Fore.RED)
            sys.exit(1)
    
    # Validate multi-goob
    if args.multi_goob and not args.url and not args.request_file:
        print_message("[!] Error: --multi-goob requires a URL or --request-file with GOOB placeholders", args.silent, Fore.RED)
        sys.exit(1)
    
    # Validate match-header
    if args.match_header:
        for header in args.match_header:
            if ":" not in header:
                print_message(f"[!] Warning: Invalid header format '{header}'. Expected 'Key:Value'", args.silent, Fore.YELLOW)
                args.match_header.remove(header)
    
    # Determine SSL verification
    args.verify_ssl = not (args.ignore_ssl and not args.no_ignore_ssl)
    
    return args

def load_wordlist(wordlist_path, encoding="utf-8", silent=False):
    """Load words from the wordlist file with specified encoding."""
    try:
        words = []
        try:
            with open(wordlist_path, "r", encoding=encoding) as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        words.append(stripped)
        except UnicodeDecodeError:
            print_message(f"[!] Warning: Failed to decode {wordlist_path} with {encoding}. Retrying with latin-1...", silent, Fore.YELLOW)
            with open(wordlist_path, "r", encoding="latin-1") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        words.append(stripped)
        except FileNotFoundError:
            print_message(f"[!] Wordlist file not found: {wordlist_path}", silent, Fore.RED)
            sys.exit(1)
        return words
    except Exception as e:
        print_message(f"[!] Error loading wordlist: {str(e)}", silent, Fore.RED)
        sys.exit(1)

def parse_request_file(file_path, silent=False):
    """Parse a raw HTTP request file into method, path, headers, and body."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        headers_end = lines.index("\n") if "\n" in lines else len(lines)
        header_lines = lines[:headers_end]
        body_lines = lines[headers_end + 1:] if headers_end < len(lines) else []
        
        first_line = header_lines[0].strip()
        try:
            method, path, _ = first_line.split(" ", 2)
        except ValueError:
            print_message("[!] Error: Invalid request file format. First line must be like 'POST /path HTTP/1.1'", silent, Fore.RED)
            sys.exit(1)
        
        headers = {}
        for line in header_lines[1:]:
            line = line.strip()
            if line:
                try:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
                except ValueError:
                    print_message(f"[!] Warning: Invalid header in request file: '{line}'. Skipping.", silent, Fore.YELLOW)
        
        if "Host" not in headers:
            print_message("[!] Error: Request file must include a 'Host' header", silent, Fore.RED)
            sys.exit(1)
        
        body = "".join(body_lines).strip()
        
        return {
            "method": method,
            "path": path,
            "headers": headers,
            "body": body
        }
    except FileNotFoundError:
        print_message(f"[!] Error: Request file not found: {file_path}", silent, Fore.RED)
        sys.exit(1)
    except Exception as e:
        print_message(f"[!] Error parsing request file: {str(e)}", silent, Fore.RED)
        sys.exit(1)

def transform_word(word, transforms):
    """Apply transformations to a word."""
    results = [word]
    if transforms:
        for t in transforms.split(","):
            t = t.strip()
            if t == "upper":
                results.append(word.upper())
            elif t == "lower":
                results.append(word.lower())
            elif t == "cap":
                results.append(word.capitalize())
            elif t.startswith("append_"):
                suffix = t.split("_", 1)[1]
                results.append(word + suffix)
    return results

def make_request(url, word, method, filter_code, filter_size, no_color, headers, cookies, follow_redirects, proxy, base64_encode, user_agent, request_file, rps, extensions, verbose, verify_ssl, match_regex, timeout, total_requests, completed_requests, lock, transform, multi_goob, match_header, silent):
    """Send HTTP request and process response with rate limiting."""
    global request_count, last_reset_time
    
    word_variations = transform_word(word, transform)
    if extensions:
        extended = []
        for w in word_variations:
            extended.append(w)
            extended.extend([f"{w}.{ext}" for ext in extensions])
        word_variations = extended
    
    results = []
    goob_count = (url.count("GOOB") if url else 0) + (parse_request_file(request_file)["body"].count("GOOB") if request_file else 0)
    
    if multi_goob and goob_count > 1:
        if multi_goob == "combo":
            combinations = [(v1, v2) for v1 in word_variations for v2 in word_variations]
        else:
            combinations = [(v, v) for v in word_variations]
    else:
        combinations = [(v, None) for v in word_variations]
    
    for variation, variation2 in combinations:
        try:
            if rps is not None:
                with rate_limit_lock:
                    current_time = time.time()
                    if current_time - last_reset_time >= 1:
                        request_count = 0
                        last_reset_time = current_time
                    
                    while request_count >= rps:
                        sleep_time = 1 - (current_time - last_reset_time)
                        if sleep_time > 0:
                            time.sleep(sleep_time)
                        current_time = time.time()
                        if current_time - last_reset_time >= 1:
                            request_count = 0
                            last_reset_time = current_time
                    
                    request_count += 1

            # Update progress before sending request
            with lock:
                completed_requests[0] += 1
                print_progress(completed_requests[0], total_requests, silent)

            if base64_encode:
                variation = base64.b64encode(variation.encode()).decode()

            request_kwargs = {
                "timeout": timeout,
                "verify": verify_ssl,
                "allow_redirects": follow_redirects
            }

            if request_file:
                req_data = parse_request_file(request_file, silent)
                target_method = req_data["method"]
                target_path = req_data["path"]
                req_headers = req_data["headers"]
                req_body = req_data["body"]

                scheme = "http"
                if url:
                    parsed_url = urlparse(url)
                    scheme = parsed_url.scheme or "http"
                target_host = req_headers["Host"]
                target_url = f"{scheme}://{target_host}{target_path}"

                if req_body:
                    target_body = req_body.replace("GOOB", variation)
                    if variation2 and multi_goob:
                        target_body = target_body.replace("GOOB", variation2)
                    request_kwargs["data"] = target_body
                else:
                    target_url = target_url.replace("GOOB", variation)
                    if variation2 and multi_goob:
                        target_url = target_url.replace("GOOB", variation2)

                header_dict = req_headers.copy()
            else:
                target_method = method
                target_url = url.replace("GOOB", variation)
                if variation2 and multi_goob:
                    target_url = target_url.replace("GOOB", variation2)
                header_dict = {"User-Agent": "GoobFuzz v1.0"}

            if user_agent:
                header_dict["User-Agent"] = user_agent
            if headers:
                for h in headers:
                    try:
                        key, value = h.split(":", 1)
                        key = key.strip()
                        value = value.strip()
                        if key.lower() != "user-agent" or not user_agent:
                            header_dict[key] = value
                    except ValueError:
                        print_message(f"[!] Warning: Invalid header format '{h}'. Expected 'Key: Value'. Skipping.", silent, Fore.YELLOW)
                        continue
            request_kwargs["headers"] = header_dict

            if cookies:
                cookie_dict = {}
                try:
                    for c in cookies.split(";"):
                        if "=" in c:
                            key, value = c.split("=", 1)
                            cookie_dict[key.strip()] = value.strip()
                        else:
                            print_message(f"[!] Warning: Invalid cookie format '{c}'. Expected 'key=value'. Skipping.", silent, Fore.YELLOW)
                    if cookie_dict:
                        request_kwargs["cookies"] = cookie_dict
                except ValueError:
                    print_message(f"[!] Warning: Invalid cookies format '{cookies}'. Expected 'key=value; key2=value2'. Skipping.", silent, Fore.YELLOW)

            if proxy:
                request_kwargs["proxies"] = {"http": proxy, "https": proxy}

            request_kwargs["method"] = target_method
            request_kwargs["url"] = target_url

            response = requests.request(**request_kwargs)

            status_code = response.status_code
            content_length = len(response.content)

            if filter_code and str(status_code) in filter_code:
                continue
            if filter_size and content_length == filter_size:
                continue

            if status_code == 404 and not verbose:
                continue

            if match_regex:
                if not re.search(match_regex, response.text):
                    continue

            if match_header:
                header_matched = False
                for header in match_header:
                    try:
                        key, value = header.split(":", 1)
                        key, value = key.strip(), value.strip()
                        if key in response.headers and value in response.headers[key]:
                            header_matched = True
                            break
                    except ValueError:
                        print_message(f"[!] Warning: Invalid header format '{header}'. Expected 'Key:Value'", silent, Fore.YELLOW)
                        continue
                if not header_matched:
                    continue

            result = f"[Status: {status_code}] [Size: {content_length}] [URL: {target_url}]"

            if not no_color:
                if 200 <= status_code < 300:
                    result = f"{Fore.GREEN}{result}{Style.RESET_ALL}"
                elif 300 <= status_code < 400:
                    result = f"{Fore.CYAN}{result}{Style.RESET_ALL}"
                elif 400 <= status_code < 500:
                    result = f"{Fore.YELLOW}{result}{Style.RESET_ALL}"
                else:
                    result = f"{Fore.RED}{result}{Style.RESET_ALL}"

            results.append((result, status_code, content_length, target_url))

        except requests.RequestException as e:
            if verbose:
                if not no_color:
                    results.append((f"{Fore.RED}[!] Error with {variation}: {str(e)}{Style.RESET_ALL}", None, None, None))
                else:
                    results.append((f"[!] Error with {variation}: {str(e)}", None, None, None))
    
    return results

def worker(queue, url, method, filter_code, filter_size, no_color, headers, cookies, follow_redirects, proxy, base64_encode, user_agent, request_file, rps, extensions, verbose, verify_ssl, match_regex, timeout, total_requests, completed_requests, lock, transform, multi_goob, match_header, silent, results):
    """Worker function for threading."""
    while not queue.empty():
        word = queue.get()
        request_results = make_request(
            url, word, method, filter_code, filter_size, no_color, headers, cookies, follow_redirects, proxy, base64_encode, user_agent, request_file, rps, extensions, verbose, verify_ssl, match_regex, timeout, total_requests, completed_requests, lock, transform, multi_goob, match_header, silent
        )
        with lock:
            for result, status_code, content_length, target_url in request_results:
                if result and status_code:
                    print(result)
                    results.append((status_code, content_length, target_url))
        queue.task_done()

def save_results(results, output_file, verbose, silent):
    """Save results to the output file."""
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            for status_code, content_length, url in results:
                f.write(f"[Status: {status_code}] [Size: {content_length}] [URL: {url}]\n")
        print_message(f"[*] Results saved to {output_file}", silent, Fore.BLUE)

def main():
    args = parse_args()

    words = load_wordlist(args.wordlist, args.encoding, args.silent)
    if not args.silent:
        print_message(f"[*] Loaded {len(words)} words from {args.wordlist}", args.silent, Fore.BLUE)

    if args.randomize:
        random.shuffle(words)
        print_message("[*] Wordlist randomized", args.silent, Fore.BLUE)

    if args.rps is not None and args.rps > args.threads * 10:
        print_message(f"[!] Warning: --rps ({args.rps}) is high relative to thread count ({args.threads}). Effective RPS may be lower.", args.silent, Fore.YELLOW)

    transform_count = len(transform_word("test", args.transform)) if args.transform else 1
    total_requests = len(words) * transform_count * (1 + len(args.extensions))
    if args.multi_goob == "combo":
        goob_count = (args.url.count("GOOB") if args.url else 0) + (parse_request_file(args.request_file, args.silent)["body"].count("GOOB") if args.request_file else 0)
        if goob_count > 1:
            total_requests *= transform_count * (1 + len(args.extensions))
            print_message(f"[!] Warning: --multi-goob combo increases requests to {total_requests}", args.silent, Fore.YELLOW)

    print_message(f"[*] Total requests to process: {total_requests}", args.silent, Fore.BLUE)

    filter_code = args.filter_code.split(",") if args.filter_code else []
    filter_size = args.filter_size
    match_regex = args.match_regex if args.match_regex else None

    queue = Queue()
    for word in words:
        queue.put(word)
    results = []
    lock = threading.Lock()

    print_message(f"[*] Starting fuzzing with {args.threads} threads{' at ' + str(args.rps) + ' RPS' if args.rps else ''}...", args.silent, Fore.BLUE)
    start_time = time.time()
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(
            target=worker,
            args=(
                queue, args.url, args.method, filter_code, args.filter_size, args.no_color,
                args.headers, args.cookies, args.follow_redirects, args.proxy, args.base64,
                args.user_agent, args.request_file, args.rps, args.extensions, args.verbose,
                args.verify_ssl, match_regex, args.timeout, total_requests,
                completed_requests, lock, args.transform, args.multi_goob, args.match_header,
                args.silent, results
            ),
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print_message("", args.silent)  # Clear progress line

    save_results(results, args.output, args.verbose, args.silent)

    elapsed_time = time.time() - start_time
    print_message(f"[*] Fuzzing completed in {elapsed_time:.2f} seconds", args.silent, Fore.BLUE)

if __name__ == "__main__":
    no_color = "--no-color" in sys.argv
    silent = "--silent" in sys.argv
    display_welcome_message(no_color, silent)
    
    try:
        main()
    except SystemExit:
        sys.exit(0)
