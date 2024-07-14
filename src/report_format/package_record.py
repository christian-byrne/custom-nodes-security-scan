""""""

from utils.config import Config
from utils.log import Logger

from rich import print
from typing import List, Dict

logger = Logger(__name__, Config()["log_level"])()


class PackageRecordBuilder:
    def __init__(self):
        self.config = Config()
        self.record = {}

    def build(self):
        tmp = self.record
        del self.record
        return tmp

    @staticmethod
    def get_severity_css_color(z_score: float):
        if z_score > 2:
            return "var(--danger)"
        elif z_score > 1:
            return "var(--orange)"
        elif z_score > 0:
            return "var(--warning)"
        else:
            return "var(--success)"

    def from_(self, package_name):
        self.record = {
            "package_name": package_name,
            "bandit_report_url": f"{package_name}-bandit.html",
            "sort_key": 0,
            "risk_level": "<span style='color: var(--green);'>0</span>",
            "z_score": "0.0",
            "yara_report_url": f"{package_name}-yara.html",
            "failed_yara_tests": "None ✅",
            "failed_bandit_tests": "None ✅",
            "github_url": "https://github.com",
        }
        return self

    def with_sort_key(self, sort_key):
        if sort_key:
            self.record["sort_key"] = sort_key
        return self

    def with_z_score(self, z_score):
        self.record["risk_level_color"] = self.get_severity_css_color(z_score)
        # Don't show negative z-scores as they don't make sense to most people possibly
        # z_score = max(0, z_score)
        self.record["z_score"] = f"{z_score:.2f}"
        self.record["risk_level"] = f"{z_score:.2f}"
        return self

    def with_failed_tests(
        self, failed_yara_tests: List[str], failed_bandit_tests: List[str]
    ):
        if failed_yara_tests:
            self.record["failed_yara_tests"] = ", ".join(failed_yara_tests)
        if failed_bandit_tests:
            self.record["failed_bandit_tests"] = ", ".join(failed_bandit_tests)
        return self

    def with_github_url(self, github_url):
        if github_url:
            self.record["github_url"] = github_url
        return self
