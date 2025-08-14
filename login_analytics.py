"""
login_analytics.py
Reusable functions for collecting and summarizing weekly webpage access data.
"""

from dataclasses import dataclass
from typing import List, Dict, Tuple
from urllib.parse import urlparse

@dataclass(frozen=True)
class Entry:
    name: str
    top_webpage: str
    days_per_week: int

def normalize_url(url: str) -> str:
    """Normalize a URL or domain to a consistent form (scheme-less, lowercase, no trailing slash)."""
    if not url:
        return url
    url = url.strip().lower()
    # If it's missing a scheme, urlparse treats it as path. Add scheme to parse, then strip it.
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.netloc or parsed.path
    host = host.strip("/")
    return host

def validate_days(days: int) -> int:
    """Clamp days to the [0, 7] range and return it as int."""
    try:
        d = int(days)
    except (TypeError, ValueError):
        raise ValueError("Days per week must be an integer between 0 and 7.")
    if d < 0 or d > 7:
        raise ValueError("Days per week must be between 0 and 7.")
    return d

def make_entry(name: str, top_webpage: str, days_per_week: int) -> Entry:
    """Create a validated Entry object."""
    if not name or not name.strip():
        raise ValueError("Name cannot be empty.")
    normalized = normalize_url(top_webpage)
    if not normalized:
        raise ValueError("Top webpage/domain cannot be empty.")
    days = validate_days(days_per_week)
    return Entry(name=name.strip(), top_webpage=normalized, days_per_week=days)

def summarize(entries: List[Entry]) -> Dict[str, Dict[str, object]]:
    """Summarize by top_webpage: total users, avg days, min, max, and per-user breakdown.

    Returns:
        {
          'example.com': {
              'total_users': 3,
              'avg_days_per_week': 4.7,
              'min_days': 2,
              'max_days': 7,
              'users': [('Alice', 5), ('Bob', 2), ('Eve', 7)]
          },
          ...
        }
    """
    if not entries:
        return {}

    by_site: Dict[str, List[Tuple[str, int]]] = {}
    for e in entries:
        by_site.setdefault(e.top_webpage, []).append((e.name, e.days_per_week))

    summary: Dict[str, Dict[str, object]] = {}
    for site, user_days in by_site.items():
        days_list = [d for _, d in user_days]
        avg = sum(days_list) / len(days_list)
        summary[site] = {
            'total_users': len(user_days),
            'avg_days_per_week': round(avg, 2),
            'min_days': min(days_list),
            'max_days': max(days_list),
            'users': sorted(user_days, key=lambda x: x[0].lower()),
        }
    return summary

def to_pretty_report(entries: List[Entry]) -> str:
    """Return a human-readable string report for the given entries."""
    if not entries:
        return "No entries recorded."

    header = ["Recorded access (days/week) by user:"]
    for e in sorted(entries, key=lambda x: (x.top_webpage, x.name.lower())):
        header.append(f" - {e.name}: {e.days_per_week}/7 on {e.top_webpage}")
    header.append("")
    header.append("Summary by site:")

    summ = summarize(entries)
    if not summ:
        header.append(" (no data)")
        return "\n".join(header)

    for site, s in sorted(summ.items(), key=lambda kv: kv[0]):
        header.append(
            f" * {site}: users={s['total_users']}, avg={s['avg_days_per_week']}/7, min={s['min_days']}, max={s['max_days']}"
        )
        for name, days in s['users']:
            header.append(f"    - {name}: {days}/7")
    return "\n".join(header)
