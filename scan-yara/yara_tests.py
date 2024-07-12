from pathlib import Path

import yara

from dir_manager import DirManager
from _types import Match
from utils import report_time_taken

from rich import print
from rich.progress import track
from typing import List, Optional, Dict


class YaraConfig:
    MATCH_EXTENSIONS = [".yara", ".yar", ".rules"]

    def __init__(self, rules_dir: Path, exlcude_tests: Optional[List[str]] = None):
        self.dir = DirManager(
            rules_dir, match_phrases=YaraConfig.MATCH_EXTENSIONS, exclude=exlcude_tests
        )

    def truncate_tests(self, max_tests: int):
        if not self.dir.children:
            self.dir.set_contents()
        self.dir.children = dict(list(self.dir.children.items())[:max_tests])

    def __len__(self):
        return self.dir.contents_ct


class TestsManager:
    def __init__(self, config: YaraConfig, auto_init_rules: Optional[bool] = True):
        self.config = config
        if auto_init_rules:
            self.rules = self.init_rules()

    @report_time_taken
    def identify_problematic_test_files(self):
        problematic_files = []
        for test_name, path in self.config.dir.get_contents().items():
            try:
                yara.compile(str(path))
            except yara.Error as e:
                problematic_files.append(f"Error in {test_name} ({path}): {e}")
        return problematic_files

    @report_time_taken
    def init_rules(self) -> yara.Rules:
        return yara.compile(filepaths=self.config.dir.get_contents())

    @report_time_taken
    def run_all_on_dir(self, dir: DirManager) -> Dict[Path, List[Match]]:
        matches = {}
        for path in track(dir.get_all_filepaths(), description="Running tests..."):
            res = self.run_test(path)
            if res:
                matches[path] = res
        return matches

    def run_test(self, path: Path) -> List[Match]:
        matches = self.rules.match(str(path))
        return matches

    def __str__(self):
        return f"TestsManager with {len(self.config)} rules: {self.config.dir.get_all_filenames()}"
