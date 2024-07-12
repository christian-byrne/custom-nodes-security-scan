"""https://yara.readthedocs.io/en/latest/yarapython.html"""

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), "."))
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from pathlib import Path
import time
import json

from yara_tests import YaraConfig, TestsManager
from dir_manager import DirManager
from test_report import Report

from rich import print


print("Starting yara_scan...")

with open(Path(__file__).parent / "config.json") as f:
    constants = json.load(f)

config = YaraConfig(
    Path(constants["RULES_RELPATH"]), exlcude_tests=constants["EXCLUDE_TESTS"]
)
config.truncate_tests(constants["MAX_TESTS"])


def debug_tests_database():
    """Run to fix errors or add bad tests to the exclude list in config"""
    tests = TestsManager(config, auto_init_rules=False)
    x = tests.identify_problematic_test_files()
    for i in x:
        print(i)
    exit()


tests = TestsManager(config)
log_file = Path("results.log")
with log_file.open("w") as f:
    f.write(f"Log for tests done on {time.strftime('%c')}\n")

for node_dir in Path(constants["CUSTOM_NODES_DIR"]).iterdir():
    if node_dir.is_dir() and node_dir.name not in constants["EXCLUDE_NODES"]:
        test_dir = DirManager(node_dir, exclude=constants["EXCLUDE_IN_NODE_DIRS"])
        results = tests.run_all_on_dir(test_dir)
        Report(results, node_dir.name, Path(constants["REPORTS_DIR"])).set_test_paths(
            tests.config.dir.get_all_filenames()
        ).preprocess_results().truncate_testnames().write_to_json().populate_template()
