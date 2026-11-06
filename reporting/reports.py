import csv
import json

from datetime import datetime, timezone
from html import escape

from config import REPORTS


def generate(metadata, findings):

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    base = REPORTS / f"vulnscope_{stamp}"

    payload = {
        "metadata": metadata,
        "findings": findings,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat()
    }

    json_path = base.with_suffix(".json")
    csv_path = base.with_suffix(".csv")
    html_path = base.with_suffix(".html")

    json_path.write_text(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    columns = [
        "severity",
        "risk_score",
        "title",
        "detail",
        "recommendation"
    ]

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=columns
        )

        writer.writeheader()

        for finding in findings:

            writer.writerow({
                key: finding.get(key, "")
                for key in columns
            })

    rows = ""

    for finding in findings:

        cells = "".join(
            f"<td>{escape(str(finding.get(key, '')))}</td>"
            for key in columns
        )

        rows += f"<tr>{cells}</tr>"

    headers = "".join(
        f"<th>{escape(key.title())}</th>"
        for key in columns
    )

    target = escape(str(metadata.get("target", "")))
    started = escape(str(metadata.get("started", "")))
    finished = escape(str(metadata.get("finished", "")))

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScope Security Report</title>

<style>
body {{
    font-family: Arial, sans-serif;
    margin: 30px;
    background: #f5f6f8;
    color: #222;
}}

main {{
    max-width: 1200px;
    margin: auto;
    background: white;
    padding: 25px;
    border-radius: 10px;
}}

table {{
    border-collapse: collapse;
    width: 100%;
}}

td, th {{
    border: 1px solid #ccc;
    padding: 9px;
    text-align: left;
    vertical-align: top;
    overflow-wrap: anywhere;
}}

th {{
    background: #eee;
}}

.note {{
    color: #555;
    font-size: 13px;
}}
</style>
</head>

<body>
<main>

<h1>VulnScope Security Assessment</h1>

<p><b>Target:</b> {target}</p>
<p><b>Started:</b> {started}</p>
<p><b>Finished:</b> {finished}</p>
<p><b>Findings:</b> {len(findings)}</p>

<table>
<thead>
<tr>{headers}</tr>
</thead>

<tbody>
{rows}
</tbody>
</table>

<p class="note">
Automated observations are not proof of exploitability
or proof that a system has no vulnerabilities.
Manually validate findings.
</p>

</main>
</body>
</html>
"""

    html_path.write_text(
        html_content,
        encoding="utf-8"
    )

    return {
        "HTML": html_path,
        "JSON": json_path,
        "CSV": csv_path
    }
