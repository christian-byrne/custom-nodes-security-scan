from pathlib import Path
import random

from utils import report_time_taken

from typing import List, Generator, Optional, Dict
from rich import print


class DirManager:
    def __init__(
        self,
        root_dir: Path,
        match_phrases: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ):
        if not isinstance(root_dir, Path):
            root_dir = Path(root_dir)
        if not root_dir.exists():
            raise FileNotFoundError(f"Directory {root_dir} does not exist.")

        self.root_dir = root_dir
        self.match_phrases = match_phrases
        self.exclude = exclude
        self.children = None
        self.contents_ct = 0

    def set_root_dir(self, root_dir: Path):
        if not root_dir.exists():
            raise FileNotFoundError(f"Directory {root_dir} does not exist.")
        self.root_dir = root_dir

    def get_root_dir(self) -> Path:
        return self.root_dir

    def get_contents(self) -> Dict[str, Path]:
        if self.children is None or len(self.children) == 0:
            self.set_contents()
        self.contents_ct = len(self.children)
        return self.children

    def get_all_filenames(self) -> List[str]:
        return list(self.get_contents().keys())

    def get_all_filepaths(self) -> List[Path]:
        return list(self.get_contents().values())

    @report_time_taken
    def set_contents(self):
        self.children = {}
        for item in DirManager.recursive_search(
            self.root_dir, self.match_phrases, self.exclude
        ):
            file = Path(str(item)[:])
            filename = file.stem
            while filename in self.children:
                if file == self.root_dir:
                    raise KeyError(f"Cannot resolve duplicate key {item}")
                filename += file.parent.stem
            self.children[str(filename)] = str(item.resolve())

    def get_n_random(self, n: int) -> List[Path]:
        return random.sample(
            DirManager.recursive_search(
                self.root_dir, match_phrases=self.match_phrases, exclude=self.exclude
            ),
            int(n),
        )

    def get_first(self) -> Path:
        return DirManager.recursive_get_first(
            self.root_dir, match_phrases=self.match_phrases, exclude=self.exclude
        )

    @staticmethod
    def recursive_search(
        root_dir: Path,
        match_phrases: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> Generator[Path, None, None]:
        for item in root_dir.iterdir():
            if item.is_dir() and (not exclude or item.name not in exclude):
                yield from DirManager.recursive_search(item, match_phrases, exclude)
            elif not match_phrases or item.suffix in match_phrases:
                if not exclude or item.name not in exclude:
                    yield item

    @staticmethod
    def recursive_get_first(
        root_dir: Path,
        match_phrases: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> Path:
        for item in root_dir.iterdir():
            if item.is_dir() and (not exclude or item.name not in exclude):
                return DirManager.recursive_get_first(item, match_phrases, exclude)
            elif not match_phrases or item.suffix in match_phrases:
                if not exclude or item.name not in exclude:
                    return item

    def __len__(self):
        return self.contents_ct

    def __str__(self):
        return f"DirManager for {self.root_dir} with {len(self)} items"
