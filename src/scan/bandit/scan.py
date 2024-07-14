"""Python version of Bandit scanner.

plugin_name_pattern = "*.py"

RANKING = ["UNDEFINED", "LOW", "MEDIUM", "HIGH"]
RANKING_VALUES = {"UNDEFINED": 1, "LOW": 3, "MEDIUM": 5, "HIGH": 10}
CRITERIA = [("SEVERITY", "UNDEFINED"), ("CONFIDENCE", "UNDEFINED")]

# add each ranking to globals, to allow direct access in module name space
for rank in RANKING:
    globals()[rank] = rank

CONFIDENCE_DEFAULT = "UNDEFINED"

# A list of values Python considers to be False.
# These can be useful in tests to check if a value is True or False.
# We don't handle the case of user-defined classes being false.
# These are only useful when we have a constant in code. If we
# have a variable we cannot determine if False.
# See https://docs.python.org/3/library/stdtypes.html#truth-value-testing
FALSE_VALUES = [None, False, "False", 0, 0.0, 0j, "", (), [], {}]

# override with "log_format" option in config file
log_format_string = "[%(module)s]\t%(levelname)s\t%(message)s"

# Directories to exclude by default
EXCLUDE = (
    ".svn",
    "CVS",
    ".bzr",
    ".hg",
    ".git",
    "__pycache__",
    ".tox",
    ".eggs",
    "*.egg",
)
"""

import json
from pathlib import Path

from bandit.core.issue import Issue
from bandit.core import config as bandit_config
from bandit.core import manager as bandit_manager
from bandit.core import test_set as bandit_test_set
from bandit.formatters.html import report

from utils.config import Config
from utils.peformance_logging import report_time_taken
from utils.log import Logger

logger = Logger(__name__, Config()["log_level"])()


class BanditScan:
    def __init__(self):
        self.config = Config()
        self.subdir_scores = {}
        self.test_categories = {}
        self.include_props = [
            "severity",
            "confidence",
            "fname",
            "lineno",
            "linerange",
            "col_offset",
            "end_col_offset",
        ]
        self.bandit_config = bandit_config.BanditConfig()
        self.test_set = bandit_test_set.BanditTestSet(self.bandit_config)
        self.load_packages()

    @report_time_taken
    def load_packages(self):
        self.package_paths = []
        target_dir = Path(self.config["target_dir"])
        for path in target_dir.iterdir():
            is_excluded = any(
                [path.match(exclude) for exclude in self.config["exclude_packages"]]
            )
            if path.is_dir() and not is_excluded:
                self.package_paths.append(path)

        return self

    @report_time_taken
    def run_tests(self):
        for package in self.package_paths:
            logger.info(
                f"Running bandit tests on all python files in {package} and subdirectories"
            )
            bandit_mgr = bandit_manager.BanditManager(self.bandit_config, self.test_set)
            bandit_mgr.discover_files([str(package)], recursive=True)
            bandit_mgr.run_tests()
            filepath = (
                self.config.get_proj_root()
                / self.config["reports_dirname"]
                / f"{package.name}-bandit.html"
            )
            logger.debug(f"Writing bandit report for {package.name} to {filepath}")
            filobj = open(filepath, "w")
            report(
                bandit_mgr,
                filobj,
                "UNDEFINED",
                "UNDEFINED",
                lines=self.config["max_snippet_lines"],
            )
            filobj.close()

            for issue in bandit_mgr.results:
                self._add_issue(issue)

        return self

    def _get_package_name(self, fname: str):
        return Path(fname).relative_to(self.config["target_dir"]).parts[0]

    def _add_issue(self, issue: Issue):
        if issue.test_id in self.config["exclude_tests_bandit"]:
            return

        if issue.test_id not in self.test_categories:
            self.test_categories[issue.test_id] = {
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

        for prop in self.include_props:
            self.test_categories[issue.test_id][prop].append(getattr(issue, prop))

        package_name = self._get_package_name(issue.fname)
        self.test_categories[issue.test_id]["node_name"].append(package_name)
        issue_fi_rel_path = Path(issue.fname).relative_to(self.config["target_dir"])
        self.test_categories[issue.test_id]["relpath"].append(str(issue_fi_rel_path))
        self.test_categories[issue.test_id]["code"].append(issue.get_code())
        self._update_scores(issue, package_name)
        self.log_scores()

    def _update_scores(self, issue: Issue, subdir: str):
        match issue.severity:
            case "HIGH":
                score = 10
            case "MEDIUM":
                score = 3
            case "LOW":
                score = 0.16
            case _:
                score = 0.16
        match issue.confidence:
            case "HIGH":
                score *= 1
            case "MEDIUM":
                score *= 0.8
            case "LOW":
                score *= 0.6
            case _:
                score *= 0.6

        if subdir not in self.subdir_scores:
            self.subdir_scores[subdir] = {
                "score": 0,
                "failed_tests": [],
            }
        self.subdir_scores[subdir]["score"] += score
        self.subdir_scores[subdir]["failed_tests"].append(issue.test_id)

    def log_scores(self):
        log_path = (
            self.config.get_proj_root()
            / self.config["reports_dirname"]
            / "scores"
            / "bandit-scores.json"
        )
        with open(log_path, "w") as f:
            json.dump(self.subdir_scores, f, indent=4)

        return self
