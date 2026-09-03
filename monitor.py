import argparse
import csv
import json
from typing import Any, Dict, List

from ai_leak_monitor import build_default_monitor


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze password leak risk using verified breach intelligence sources."
    )
    parser.add_argument("passwords", nargs="*", help="passwords to monitor")
    parser.add_argument("-j", "--json", action="store_true", help="export results to monitor_results.json")
    parser.add_argument("-cv", "--output-csv", action="store_true", help="export results to monitor_results.csv")
    return parser.parse_args()


def export_json(results: List[Dict[str, Any]]) -> None:
    with open("monitor_results.json", "w", encoding="utf-8") as outfile:
        json.dump(results, outfile, indent=2)


def export_csv(results: List[Dict[str, Any]]) -> None:
    with open("monitor_results.csv", "w", newline="", encoding="utf-8") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(["Password", "RiskScore", "RiskLevel", "LeakCount", "Signals", "SourceErrors"])
        for result in results:
            writer.writerow(
                [
                    result["password"],
                    result["risk_score"],
                    result["risk_level"],
                    result["total_leak_count"],
                    json.dumps(result["signals"], separators=(",", ":")),
                    ";".join(result["source_errors"]),
                ]
            )


def main() -> None:
    args = parse_args()

    if not args.passwords:
        return

    monitor = build_default_monitor()
    results = [monitor.scan_password(password) for password in args.passwords]

    for result in results:
        print(
            f"{result['password']}: {result['risk_level']} "
            f"(score={result['risk_score']}, leaks={result['total_leak_count']})"
        )

    if args.json:
        export_json(results)
    elif args.output_csv:
        export_csv(results)


if __name__ == "__main__":
    main()
