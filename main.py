import argparse
import csv
import hashlib
import json
from requests import RequestException
import requests

RANGE_API_URL = "https://api.pwnedpasswords.com/range/"


def password_hash(password):
    sha1_hash_upper = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first_5char, tail = sha1_hash_upper[:5], sha1_hash_upper[5:]
    return first_5char, tail


def pwned_api_check(first, tail):
    url = RANGE_API_URL + first
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return int(count)
    return 0


def get_password_leaks(password):
    first, tail = password_hash(password)
    return pwned_api_check(first, tail)


def risk_level(count):
    if count == 0:
        return "Safe for now (not found in known breaches)."
    if count < 100:
        return "Low risk: leaked before, change it."
    if count < 10000:
        return "High risk: heavily exposed, change now."
    return "Critical risk: massively exposed password."


def build_parser():
    parser = argparse.ArgumentParser(description="Simple password breach checker")
    parser.add_argument("passwords", nargs="*", help="Passwords to check")
    parser.add_argument(
        "--json-file",
        default="",
        help="Save results to a JSON file (example: results.json)",
    )
    parser.add_argument(
        "--csv-file",
        default="",
        help="Save results to a CSV file (example: results.csv)",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    passwords = args.passwords
    if not passwords:
        entered = input("Enter password: ").strip()
        if entered:
            passwords = [entered]

    if not passwords:
        print("No password provided.")
        raise SystemExit(1)

    results = []
    for password in passwords:
        try:
            count = get_password_leaks(password)
            result = {
                "password": password,
                "count": count,
                "exposed": count > 0,
                "risk": risk_level(count),
            }
            results.append(result)
            print(f"{password}: {count} leaks -> {result['risk']}")
        except RequestException as error:
            result = {
                "password": password,
                "count": None,
                "exposed": None,
                "risk": "Could not check password right now.",
                "error": str(error),
            }
            results.append(result)
            print(f"{password}: error checking breach data ({error})")

    if args.json_file:
        with open(args.json_file, "w", encoding="utf-8") as outfile:
            json.dump(results, outfile, indent=2)
        print(f"Saved JSON report: {args.json_file}")

    if args.csv_file:
        with open(args.csv_file, "w", newline="", encoding="utf-8") as outfile:
            writer = csv.writer(outfile)
            writer.writerow(["Password", "Count", "Exposed", "Risk", "Error"])
            for item in results:
                writer.writerow(
                    [
                        item["password"],
                        item["count"],
                        item["exposed"],
                        item["risk"],
                        item.get("error", ""),
                    ]
                )
        print(f"Saved CSV report: {args.csv_file}")


if __name__ == "__main__":
    main()
