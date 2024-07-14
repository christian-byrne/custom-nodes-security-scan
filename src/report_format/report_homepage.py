"""Homepage report generator"""

import os
import time
import json
import subprocess

from jinja2 import Environment, FileSystemLoader

from utils.config import Config
from utils.log import Logger
from report_format.package_record import PackageRecordBuilder

from rich import print
from typing import List, Dict

logger = Logger(__name__, Config()["log_level"])()


class HomePage:
    FILENAME = "index.html"

    def __init__(self):
        self.config = Config()
        self.records = []
        self.scores = self.load_cumulative_scores()

    def __call__(self):
        self.create_records()
        self.render()

    def render(self):
        self.records = sorted(
            self.records, key=lambda x: float(x["sort_key"]), reverse=True
        )
        templates_dir = (
            self.config.get_proj_root() / self.config["report_templates_dir_relpath"]
        )
        logger.info(f"Rendering homepage with templates from {templates_dir}")
        env = Environment(
            loader=FileSystemLoader(templates_dir),
        )
        template = env.get_template(HomePage.FILENAME)
        output_html = template.render(
            results=self.records, date=time.strftime("%Y-%m-%d %H:%M:%S")
        )
        output_file = (
            self.config.get_proj_root()
            / self.config["reports_dirname"]
            / HomePage.FILENAME
        )
        logger.info(f"Saving rendered homepage to {output_file}")
        with open(output_file, "w") as f:
            f.write(output_html)

        print(f"Saved to {output_file}")
        os.system(f"xdg-open {str(output_file)}")

    def load_cumulative_scores(self) -> Dict[str, Dict[str, float]]:
        path = (
            self.config.get_proj_root()
            / self.config["reports_dirname"]
            / "scores"
            / "cumulative-scores.json"
        )
        logger.debug(f"Loading cumulative scores from {path}")
        with open(path, "r") as f:
            return json.load(f)

    def get_package_fails(self, package_name: str, test_category: str):
        with open(
            self.config.get_proj_root()
            / self.config["reports_dirname"]
            / "scores"
            / f"{test_category}-scores.json",
            "r",
        ) as f:
            package_report = json.load(f).get(package_name, [])
            if "failed_tests" in package_report:
                return package_report["failed_tests"]
            return []

    def create_records(self):
        logger.info("Creating package records for homepage table")
        for package_name, score in self.scores.items():
            self.records.append(
                PackageRecordBuilder()
                .from_(package_name)
                .with_z_score(score["z_score"])
                .with_sort_key(score["raw"])
                .with_failed_tests(
                    self.get_package_fails(package_name, "yara"),
                    self.get_package_fails(package_name, "bandit"),
                )
                .with_github_url(self.get_github_url(package_name))
                .build()
            )

    def get_github_url(self, package_name):
        path = self.config.get_proj_root() / self.config["target_dir"] / package_name
        if not path.exists():
            logger.error(
                f"Path {path} does not exist. Did you remove this package since last scan?"
            )
        try:
            cmd = ["git", "-C", str(path), "remote", "-v"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            remotes = result.stdout.strip().split("\n")
            for remote in remotes:
                if "github.com" in remote:
                    github_url = remote.split()[1]
                    if github_url.endswith(".git"):
                        github_url = github_url[:-4]
                        github_url = github_url.split(":")[-1]
                        if not github_url.startswith("github.com/"):
                            github_url = f"github.com/{github_url}"
                        github_url = f"https://{github_url}"
                    else:
                        logger.debug(
                            f"Github url for {package_name} does not end with .git: {github_url}"
                        )
                    return github_url
        except subprocess.CalledProcessError as e:
            logger.error(f"Error retrieving remotes for {path}: {e}")
            logger.error(
                f"Command: {' '.join(cmd)}. Github url won't work for this record."
            )

        return None
