import argparse
import hashlib
import json
import sys
from typing import Callable
from urllib.error import URLError
from urllib import request


PWNED_PASSWORDS_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"


def sha1_hash(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def parse_pwned_response(response_text: str, target_suffix: str) -> int:
    target = target_suffix.upper()
    for line in response_text.splitlines():
        if not line:
            continue
        suffix, _, count = line.partition(":")
        if suffix.upper() == target:
            return int(count)
    return 0


def _default_http_get(url: str) -> str:
    with request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8")


def check_password_exposure(password: str, http_get: Callable[[str], str] = _default_http_get) -> int:
    hashed_password = sha1_hash(password)
    prefix, suffix = hashed_password[:5], hashed_password[5:]
    response_text = http_get(PWNED_PASSWORDS_RANGE_URL.format(prefix))
    return parse_pwned_response(response_text, suffix)


def ai_dark_web_assessment(breach_count: int) -> str:
    if breach_count <= 0:
        return "AI assessment: No dark-web exposure found for this password."
    if breach_count < 100:
        return "AI assessment: Password appears in breaches; replace it and avoid reuse."
    if breach_count < 10000:
        return "AI assessment: High-risk password found in many breaches. Change immediately."
    return "AI assessment: Critical risk. This password is widely exposed on the dark web."


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check whether a password appears in dark-web breach data via HaveIBeenPwned."
    )
    parser.add_argument("password", help="Password to check")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")
    parser.add_argument("--ai", action="store_true", help="Include AI-style risk assessment")
    args = parser.parse_args()

    try:
        count = check_password_exposure(args.password)
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
        print(f"Password found in breach data {count} times.")
    else:
        print("Password not found in breach data.")

    if args.ai:
        print(result["ai_assessment"])


if __name__ == "__main__":
    main()
