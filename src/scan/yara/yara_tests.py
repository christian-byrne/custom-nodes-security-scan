from pathlib import Path

import yara

from utils.dir_manager import DirManager
from scan.yara._types import Match
from utils.peformance_logging import report_time_taken
from utils.config import Config
from utils.log import Logger

from rich.progress import track
from typing import List, Optional, Dict

config = Config()
logger = Logger(__name__, config["log_level"])()


class YaraConfig:
    MATCH_EXTENSIONS = [".yara", ".yar"]

    def __init__(self):
        rules_dir = config.get_proj_root() / config["yara_rules_relpath"]
        self.dir = DirManager(
            rules_dir,
            match_phrases=YaraConfig.MATCH_EXTENSIONS,
            exclude=config["exclude_tests_yara"],
        )
        logger.info(f"YaraConfig initialized with {len(self)} rules")

    def truncate_tests(self):
        self.dir.truncate_contents(int(config["max_tests_yara"]))

    def __len__(self):
        if self.dir.contents_ct == 0:
            self.dir.set_contents()
        return self.dir.contents_ct


class TestsManager:
    def __init__(self, config: YaraConfig, auto_init_rules: Optional[bool] = True):
        self.config = config
        if auto_init_rules:
            self.rules = self.init_rules()

    @report_time_taken
    def identify_problematic_test_files(self):
        logger.info("Identifying problematic test files...")
        problematic_files = []
        for test_name, path in self.config.dir.get_contents().items():
            try:
                yara.compile(str(path))
            except yara.Error as e:
                problematic_files.append(f"Error in {test_name} ({path}): {e}")
        return problematic_files

    @report_time_taken
    def init_rules(self) -> yara.Rules:
        files = self.config.dir.get_contents()
        logger.info(f"Initializing rules from {len(files)} tests")
        return yara.compile(filepaths=files)

    @report_time_taken
    def run_all_on_dir(self, dir_: DirManager) -> Dict[Path, List[Match]]:
        logger.info(f"Running tests on all files in {dir_.root_dir}")
        matches = {}
        for path in track(
            dir_.get_all_filepaths(),
            description=f"Running tests on {dir_.root_dir.name}",
        ):
            res = self.run_test(path)
            if res:
                matches[path] = res
        return matches

    def run_test(self, path: Path) -> List[Match]:
        matches = self.rules.match(str(path))
        return matches

    def __str__(self):
        return f"TestsManager with {len(self.config)} rules: {self.config.dir.get_all_filenames()}"
