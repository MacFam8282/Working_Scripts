"""
run_login_survey.py
Execution script that uses login_analytics.py to collect user input and print a report.

Run:
    python run_login_survey.py
"""

from typing import List
from login_analytics import Entry, make_entry, to_pretty_report

def prompt_yes_no(prompt: str) -> bool:
    while True:
        ans = input(f"{prompt} [y/n]: ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("Please answer with 'y' or 'n'.")

def main():
    print("Weekly Webpage Access Survey")
    print("Enter one or more users. I'll ask for name, top webpage, and days per week (0–7).\n")

    entries: List[Entry] = []

    while True:
        name = input("User's name: ").strip()
        top_webpage = input("Top webpage or domain (e.g., example.com or https://example.com): ").strip()
        days_raw = input("How many days per week do they access it? (0–7): ").strip()

        try:
            entry = make_entry(name=name, top_webpage=top_webpage, days_per_week=days_raw)
            entries.append(entry)
            print(f"Recorded: {entry.name} -> {entry.top_webpage} {entry.days_per_week}/7\n")
        except Exception as e:
            print(f"Error: {e}\nPlease try again.\n")
            if not prompt_yes_no("Do you want to re-enter this user?"):
                pass  # skip and continue to next/new user

        if not prompt_yes_no("Add another user?"):
            break

    print("\n--- Report ---")
    print(to_pretty_report(entries))

if __name__ == "__main__":
    main()
