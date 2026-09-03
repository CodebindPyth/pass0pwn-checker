import csv
import hashlib
import json
import argparse
import requests

parser = argparse.ArgumentParser()
parser.add_argument(
    "passwords",
    nargs="*",
    help="passwords to check"
)
parser.add_argument(
    "-j", "--json",
    action="store_true",
    help="export all passwords in JSON."
)
parser.add_argument(
    "-cv", "--output-csv",
    action="store_true",
    help="export all passwords in csv"
)
args = parser.parse_args()

passwords = args.passwords
results = []

for password in passwords:

    def password_hash(password):
        sha1_hash_upper = hashlib.sha1(password.encode()).hexdigest().upper()
        first_5char, tail = sha1_hash_upper[:5], sha1_hash_upper[5:]
        return first_5char, tail

    first, tail = password_hash(password)

    def pwned_api_check(first, tail):
        url = "https://api.pwnedpasswords.com/range/" + first
        response = requests.get(url)
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == tail:
                return int(count)
        return 0

    def get_password_leaks():
        return pwned_api_check(first, tail)

    count = get_password_leaks()
    print(count)
    results.append({"password": password, "count": count})

if args.json:
    with open("passwords.json", "w") as outfile:
        json.dump(results, outfile)

elif args.output_csv:
    with open("passwords.csv", "w", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(["Password", "Count"])
        for item in results:
            writer.writerow([item["password"], item["count"]])

