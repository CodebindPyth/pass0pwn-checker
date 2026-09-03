import argparse
import hashlib
import json
import sys
from urllib.error import URLError

import requests


PWNED_PASSWORDS_RANGE_URL = "https://api.pwnedpasswords.com/range/"


def sha1_hash(value):
    return hashlib.sha1(value.encode("utf-8")).hexdigest().upper()


def parse_pwned_response(response_text, target_suffix):
    target = target_suffix.upper()
    for line in response_text.splitlines():
        if not line:
            continue
        hash_suffix, count = line.split(":")
        if hash_suffix.upper() == target:
            return int(count)
    return 0


def _default_http_get(url):
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.text


def check_password_exposure(secret, http_get=_default_http_get):
    hashed_password = sha1_hash(secret)
    prefix, suffix = hashed_password[:5], hashed_password[5:]
    response_text = http_get(PWNED_PASSWORDS_RANGE_URL + prefix)
    return parse_pwned_response(response_text, suffix)


def ai_dark_web_assessment(breach_count):
    if breach_count <= 0:
        return "AI assessment: No dark-web exposure found for this submitted credential."
    if breach_count < 100:
        return "AI assessment: Password appears in breaches; replace it and avoid reuse."
    if breach_count < 10000:
        return "AI assessment: High-risk password found in many breaches. Change immediately."
    return "AI assessment: Critical risk. This credential is widely exposed on the dark web."


def main():
    parser = argparse.ArgumentParser(
        description="Check whether a password appears in dark-web breach data via HaveIBeenPwned."
    )
    parser.add_argument("secret", help="Credential text to check")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")
    parser.add_argument("--ai", action="store_true", help="Include AI-style risk assessment")
    args = parser.parse_args()

    try:
        count = check_password_exposure(args.secret)
    except (TimeoutError, URLError, ValueError) as error:
        if args.json:
            print(json.dumps({"error": f"Unable to check dark-web data: {error}"}))
        else:
            print(f"Unable to check dark-web data: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    is_exposed = count > 0

    result = {
        "exposed": is_exposed,
        "count": count,
    }

    if args.ai:
        result["ai_assessment"] = ai_dark_web_assessment(count)

    if args.json:
        print(json.dumps(result))
        return

    if is_exposed:
        print(f"Credential found in breach data {count} times.")
    else:
        print("Credential not found in breach data.")

    if args.ai:
        print(result["ai_assessment"])


if __name__ == "__main__":
    main()
