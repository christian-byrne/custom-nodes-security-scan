import os
import sys
from scipy import stats

from bandit.core.issue import Issue
from bandit.core import config as b_config
from bandit.core import manager as b_manager
from bandit.core import test_set as b_test_set

from rich import print
from rich.panel import Panel
from rich.table import Table

custom_nodes_dir = sys.argv[1]
if not os.path.exists(custom_nodes_dir) or not os.path.isdir(custom_nodes_dir):
    raise FileNotFoundError(f"Could not find directory at {custom_nodes_dir}")

skipped_tests = [
    "B101",  # Checks for use of `assert`
    "B112",  # Checks for existence of `Try`, `Except`, `Continue`
    "B311",  # Checks for use of `random` assuming it's not cryptographically secure
]

b_conf = b_config.BanditConfig()
test_set = b_test_set.BanditTestSet(b_conf)
b_mgr = b_manager.BanditManager(b_conf, test_set)
b_mgr.discover_files([custom_nodes_dir], recursive=True)
b_mgr.run_tests()
path_truncate_delimiter = "custom_nodes"
custom_node_scores = {}

test_categories = {}
for test in b_mgr.results:
    issue: Issue = test
    code = issue.get_code()
    cwe = issue.cwe
    fdata = issue.fname
    lineno = issue.lineno
    linerange = issue.linerange

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
    score = 8 if issue.severity == "HIGH" else 4 if issue.severity == "MEDIUM" else 1
    if issue.confidence == "MEDIUM":
        score *= .8
    elif issue.confidence == "LOW":
        score *= .6

    if node_name not in custom_node_scores:
        custom_node_scores[node_name] = score
    else:
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


all_html = "<body style='font-family: Arial, sans-serif;'><h1 style='text-align: center;'>Bandit Scan Results</h1><table style='width: 100%'><tr><th>Node Name</th><th>Risk Level</th><th>Z-Score</th><th>Full Details</th></tr>"
for i in range(len(z_scores)):
    color = (
        "red"
        if z_scores[i] > 2
        else (
            "orange" if z_scores[i] > 1 else ("yellow" if z_scores[i] > 0 else "green")
        )
    )
    node_name = list(custom_node_scores.keys())[i]
    html_row = f"<tr><td style='text-align: center; font-weight: bold; font-size: 130%'>{node_name}</td><td style='color: {color}'>{scores[i]}</td><td>{z_scores[i]:.4f}</td><td><a href='{node_name}'>Details</a></td></tr>"

    all_html += html_row

with open(os.path.join(html_src_dir, "index.html"), "w") as f:
    f.write(all_html)

os.system(f"xdg-open {os.path.join(html_src_dir, 'index.html')}")
