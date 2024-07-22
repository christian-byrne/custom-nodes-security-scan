from pathlib import Path
import os
import time
from urllib.parse import quote

from infer_license import guess_file
from tabulate import tabulate

from scan.yara.yara_tests import YaraConfig
from utils.config import Config
from utils.log import Logger
from utils.dir_manager import DirManager

from typing import List

config = Config()
logger = Logger(__name__, config["log_level"])()


class YaraDocs:
    def __init__(self):
        self.target_dir = Path(config["target_dir"])
        self.yara_config = YaraConfig()
        self.all_tests = self.yara_config.dir.get_all_filepaths()
        self.yara_test_packages = os.listdir(self.yara_config.dir.root_dir)
        self.yara_wiki_path = config.get_proj_root() / "wiki" / "all-yara-tests.md"
        self.yara_wiki_sample_path = config.get_proj_root() / "wiki" / "sample-yara-tests.md"
        self.column_headers = ["Source", "Test Name", "File", "License"]
        self.sample_tests = [self.column_headers[:]]

    def update(self):
        self.init_yara_docs_md()
        table_data = self.register_test_records()
        self.write_to_md(table_data)
        logger.info(f"Updated {self.yara_wiki_path}")
        self.write_sample_tests()

    def init_yara_docs_md(self):
        with open(self.yara_wiki_path, "w") as f:
            f.write("# All Yara Tests\n\n")

    def find_license(self, start_path: Path):
        license_ = None
        for path in start_path.iterdir():
            if path.is_file() and path.name == "LICENSE":
                license_ = guess_file(path)
                if license_:
                    return license_

        return "Unknown"

    def get_test_url(self, test_abs_path: Path, test_package_abs_path: Path):
        base_url = "https://github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules"
        test_rel_path = test_abs_path.relative_to(test_package_abs_path)
        return f"{base_url}/{test_package_abs_path.name}/{test_rel_path}"

    def format_md_link(self, url: str, text: str = "source"):
        url = quote(url)
        return f"[{text}]({url})"

    def register_test_records(self) -> List[List[str]]:
        table_data = [self.column_headers[:]]
        package_license_cache = {}
        for package in self.yara_test_packages:
            has_sampled = False
            package_fullpath = self.yara_config.dir.root_dir / package
            dir_manager = DirManager(package_fullpath, match_phrases=[".yara", ".yar"])
            for test in dir_manager.get_all_filepaths():
                test = Path(test)
                test_name = test.name

                # Infer license
                if package_fullpath in package_license_cache:
                    license_ = package_license_cache[package_fullpath]
                else:
                    license_ = self.find_license(package_fullpath)
                    if license_:
                        package_license_cache[package_fullpath] = license_
                if not isinstance(license_, str):
                    license_ = license_.name

                # Get link to source on remote
                url = self.get_test_url(test, package_fullpath)
                link = self.format_md_link(url)

                record = [package, test_name.strip("."), link, license_]
                table_data.append(record)
                if not has_sampled:
                    self.sample_tests.append(record)
                    has_sampled = True

        return table_data

    def write_sample_tests(self):
        markdown_table = tabulate(self.sample_tests, headers="firstrow", tablefmt="github")
        with open(self.yara_wiki_sample_path, "w") as f:
            f.write(markdown_table)
        # Prepend every line with > to make it a quote
        with open(self.yara_wiki_sample_path, "r") as f:
            lines = f.readlines()
        with open(self.yara_wiki_sample_path, "w") as f:
            for line in lines:
                f.write(f"> {line}")

    def write_to_md(self, table_data: List[List[str]]):
        markdown_table = tabulate(table_data, headers="firstrow", tablefmt="github")
        current_time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        with open(self.yara_wiki_path, "a") as f:
            f.write("\n\n")
            f.write(f"**Total files**: {len(self.all_tests)}\n")
            f.write("\n\n")
            f.write(f"**Generated on**: {current_time_string}\n")
            f.write("\n\n")
            f.write(markdown_table)
            f.write("\n\n")
