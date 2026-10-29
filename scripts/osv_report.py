"""Summarize OSV JSON without hiding findings or changing the scanner's exit code."""

import json
from pathlib import Path
import sys


def summarize(data):
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("Incomplete OSV report: missing results array")
    packages, active, filtered, rows = set(), set(), set(), {}
    for source in data["results"]:
        for item in source["packages"]:
            package = item["package"]
            key = (package["ecosystem"], package["name"], package["version"])
            packages.add(key)
            groups = item.get("groups") or [{"ids": [entry["id"]]} for entry in item.get("vulnerabilities", [])]
            for group in groups:
                identifiers = set(group["ids"])
                if not identifiers:
                    raise ValueError("Incomplete OSV vulnerability group")
                analysis = group.get("experimental_analysis", {})
                excluded = all(analysis.get(identifier, {}).get("unimportant", False)
                               or analysis.get(identifier, {}).get("called", True) is False
                               for identifier in identifiers)
                if excluded:
                    filtered.update(identifiers)
                else:
                    active.update(identifiers)
                    rows.setdefault(key, set()).update(identifiers)
    # An ID active for any installed package must never count only as filtered.
    return packages, active, filtered - active, rows


def safe(value):
    return str(value).encode("unicode_escape").decode("ascii")


def main(path):
    packages, active, filtered, rows = summarize(json.loads(Path(path).read_text()))
    print(f"{len(packages)} distinct package/version entries; {len(active)} active advisory IDs; "
          f"{len(filtered)} additional IDs filtered by OSV's own analysis.")
    for (ecosystem, name, version), identifiers in sorted(rows.items()):
        print(f"  {safe(ecosystem)}  {safe(name)} {safe(version)}: " + ", ".join(safe(value) for value in sorted(identifiers)))
    print("The JSON retains all findings, including OSV-filtered entries. This scan does not assess the live VPS or guarantee exploitability.")


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit(f"Cannot summarize OSV report: {error}")
