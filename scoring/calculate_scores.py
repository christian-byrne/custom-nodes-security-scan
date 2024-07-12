"""Arbitrary scores just for exploratory purposes"""

import os
import time
import sys
import json
from scipy import stats
from jinja2 import Environment, FileSystemLoader
import subprocess

from bandit.core.issue import Issue
from bandit.core import config as b_config
from bandit.core import manager as b_manager
from bandit.core import test_set as b_test_set

from rich import print
from rich.panel import Panel
from rich.table import Table

target_dir = sys.argv[1]
if not os.path.exists(target_dir) or not os.path.isdir(target_dir):
    raise FileNotFoundError(f"Could not find directory at {target_dir}")

skipped_tests = [
    "B101",  # Checks for use of `assert`
    "B112",  # Checks for existence of `Try`, `Except`, `Continue`
    "B311",  # Checks for use of `random` assuming it's not cryptographically secure
]

b_conf = b_config.BanditConfig()
test_set = b_test_set.BanditTestSet(b_conf)
b_mgr = b_manager.BanditManager(b_conf, test_set)
# all_subdirs = [d for d in os.listdir(target_dir) if os.path.isdir(os.path.join(target_dir, d))]
b_mgr.discover_files([target_dir], recursive=True)
b_mgr.run_tests()
path_truncate_delimiter = "custom_nodes"
custom_node_scores = {}
custom_nodes_failed_tests = {}

test_categories = {}
for test in b_mgr.results:
    issue: Issue = test
    if issue.test_id not in test_categories:
        test_categories[issue.test_id] = {
            "cwe": issue.cwe,
            "text": issue.text,
            "test_id": issue.test_id,
            "test": issue.test,
            "ident": issue.ident,
            "code": [],
            "severity": [],
            "confidence": [],
            "fname": [],
            "node_name": [],
            "relpath": [],
            "lineno": [],
            "linerange": [],
            "col_offset": [],
            "end_col_offset": [],
        }

    test_categories[issue.test_id]["severity"].append(issue.severity)
    test_categories[issue.test_id]["confidence"].append(issue.confidence)

    test_categories[issue.test_id]["fname"].append(issue.fname)
    path_from_custom_nodes = os.path.normpath(
        str(issue.fname).split(path_truncate_delimiter)[-1]
    )
    parts = path_from_custom_nodes.split(os.sep)
    node_name = parts.pop(0)
    while node_name == "" or node_name == " ":
        if len(parts) == 0:
            raise FileExistsError(f"Could not parse node name in {issue.fname}")
        node_name = parts.pop(0)

    rel_path = os.path.join(*parts)
    test_categories[issue.test_id]["node_name"].append(node_name)
    test_categories[issue.test_id]["relpath"].append(rel_path)
    test_categories[issue.test_id]["code"].append(issue.get_code())
    test_categories[issue.test_id]["lineno"].append(issue.lineno)
    test_categories[issue.test_id]["linerange"].append(issue.linerange)
    test_categories[issue.test_id]["col_offset"].append(issue.col_offset)
    test_categories[issue.test_id]["end_col_offset"].append(issue.end_col_offset)

    # Calculate the score
    score = (
        10 if issue.severity == "HIGH" else 3 if issue.severity == "MEDIUM" else 0.16
    )
    if issue.confidence == "MEDIUM":
        score *= 0.8
    elif issue.confidence == "LOW":
        score *= 0.6

    if node_name not in custom_node_scores:
        custom_node_scores[node_name] = score
    else:
        custom_node_scores[node_name] += score

    custom_nodes_failed_tests[node_name] = custom_nodes_failed_tests.get(node_name, [])
    custom_nodes_failed_tests[node_name].append(issue.test_id)

print("Bandit scores:", custom_node_scores)

with open("scoring/bandit-scores.json", "w") as f:
    json.dump(custom_node_scores, f, indent=4)

# Add scores from yara scan

with open("scoring/yara-scores.json", "r") as f:
    yara_scores = json.load(f)

for node_name, scores in yara_scores.items():
    if node_name not in custom_node_scores:
        # TODO: fix this - bandit ignoring 1-2 dirs inexplicably
        # raise KeyError(f"Could not find node {node_name} in custom node scores")
        custom_node_scores[node_name] = 0

    score = 0
    score += scores["num_issues"] * 32
    score += scores["num_matched_patterns"] * 8
    score += scores["num_match_instances"] * 0.04
    custom_node_scores[node_name] += score


def print_results_table():
    COLORS = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "bold red",
    }

    for test_id, test_data in test_categories.items():
        if test_id in skipped_tests:
            continue

        color_severity = COLORS[test_data["severity"][0]]
        color_confidence = COLORS[test_data["confidence"][0]]
        table = Table(title="Issue Locations", show_header=True)
        table.add_column("Severity", style=color_severity)
        table.add_column("Confidence", style=color_confidence)
        table.add_column("Node Name", style="bold blue")
        table.add_column("Rel Path", style="blue")
        table.add_column("Preview of Code")
        table.add_column("Line Number")
        table.add_column("Line Range")
        table.highlight = True

        for i in range(len(test_data["severity"])):
            table.add_row(
                str(test_data["severity"][i]),
                str(test_data["confidence"][i]),
                str(test_data["node_name"][i]),
                str(test_data["relpath"][i]),
                str(test_data["code"][i]),
                str(test_data["lineno"][i]),
                str(test_data["linerange"][i]),
            )
        container_panel = Panel(
            table,
            title=f"Issue {test_data['test_id']} - {test_data['text']}",
            subtitle=f"{test_data['cwe']} ({test_data['ident']})",
        )
        print(container_panel)


scores = list(custom_node_scores.values())
z_scores = stats.zscore(scores)
this_path = os.path.dirname(os.path.realpath(__file__))
html_src_dir = sys.argv[2]
template_dir = sys.argv[3]
if not os.path.exists(template_dir) or not os.path.isdir(template_dir):
    raise FileNotFoundError(f"Could not find directory for `template_dir` arg: {template_dir}")

def get_github_url(node_name):
    path = os.path.join(target_dir, node_name)
    try:
        cmd = ["git", "-C", path, "remote", "-v"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        remotes = result.stdout.strip().split("\n")
        for remote in remotes:
            if "github.com" in remote:
                github_url = remote.split()[1]
                if github_url.endswith(".git"):
                    github_url = github_url[:-4]
                    github_url = github_url.split(":")[-1]
                    github_url = f"https://{github_url}"
                return github_url
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving remotes for {path}: {e}")

    return None


results = []
for i, node_name in enumerate(custom_node_scores):
    severity = scores[i]
    z_score = z_scores[i]
    if z_score > 2:
        color = "var(--red)"
    elif z_score > 1:
        color = "var(--orange)"
    elif z_score > 0:
        color = "var(--yellow)"
    else:
        color = "var(--green)"
    bandit_report_url = f"{node_name}"
    if not bandit_report_url.endswith(".html"):
        bandit_report_url = f"{bandit_report_url}-bandit.html"
    else:
        bandit_report_url = bandit_report_url.replace(".html", "-bandit.html")
    yara_report_url = bandit_report_url.replace("-bandit.html", "-yara.html")
    failed_yara_tests = yara_scores.get(node_name, {}).get("failed_tests", ["None ✅"])
    failed_yara_tests = ", ".join(failed_yara_tests)
    failed_bandit_tests = custom_nodes_failed_tests.get(node_name, ["None ✅"])
    failed_bandit_tests = ", ".join(failed_bandit_tests)

    results.append(
        {
            "sort_key": severity,
            "package_name": node_name,
            "risk_level": f"<span style='color: {color};'>{severity:.2f}</span>",
            "z_score": f"{z_score:.4f}",
            "bandit_report_url": bandit_report_url,
            "yara_report_url": yara_report_url,
            "failed_yara_tests": failed_yara_tests,
            "failed_bandit_tests": failed_bandit_tests,
            "github_url": get_github_url(node_name),
        }
    )


# Sort by risk level high to low
results = sorted(results, key=lambda x: float(x["sort_key"]), reverse=True)

env = Environment(loader=FileSystemLoader(template_dir))
template = env.get_template("index.html")
output_html = template.render(results=results, date=time.strftime("%Y-%m-%d %H:%M:%S"))

# Save rendered template to file
output_file = os.path.join(html_src_dir, "index.html")
with open(output_file, "w") as f:
    f.write(output_html)

print(f"Saved to {output_file}")

os.system(f"xdg-open {os.path.join(html_src_dir, 'index.html')}")
