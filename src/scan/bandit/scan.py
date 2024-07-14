"""Python version of Bandit scanner."""

import json
from pathlib import Path

from bandit.core.issue import Issue
from bandit.core import config as bandit_config
from bandit.core import manager as bandit_manager
from bandit.core import test_set as bandit_test_set

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
        self.bandit_mgr = bandit_manager.BanditManager(
            self.bandit_config, self.test_set
        )

    @report_time_taken
    def load_target_files(self):
        logger.info(f"Recursively discovering files in {self.config['target_dir']}")
        self.bandit_mgr.discover_files([self.config["target_dir"]], recursive=True)
        logger.info(f"Discovered {len(self.bandit_mgr.files_list)} python files")
        return self

    @report_time_taken
    def run_tests(self):
        logger.info(
            f"Running bandit tests on all python files in {self.config['target_dir']}"
        )
        self.bandit_mgr.run_tests()
        for issue in self.bandit_mgr.results:
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
