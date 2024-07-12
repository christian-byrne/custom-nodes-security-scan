from pathlib import Path
import time
import json

from jinja2 import Environment, FileSystemLoader

from _types import Match

from typing import List, Dict
from rich import print


class Report:
    def __init__(
        self, matches: Dict[Path, List[Match]], node_name: str, output_dir: Path
    ):
        self.matches = matches
        self.node_name = node_name
        self.output_dir = output_dir
        self.has_matches = False
        self.results = {}
        self.all_test_names = []
        self.failed_tests = []
        self.num_matches = 0
        self.num_issues = 0
        self.num_instances = 0
        self.json_path = Path("scoring/yara-scores.json")

    def write_to_json(self) -> "Report":
        with self.json_path.open("r") as f:
            current = json.load(f)
        if self.node_name not in current:
            current[self.node_name] = {}

        current[self.node_name]["num_issues"] = self.num_issues
        current[self.node_name]["num_matched_patterns"] = self.num_matches
        current[self.node_name]["num_match_instances"] = self.num_instances
        current[self.node_name]["num_failed_tests"] = len(self.failed_tests)
        current[self.node_name]["failed_tests"] = self.failed_tests

        with self.json_path.open("w") as f:
            json.dump(current, f, indent=4)
        return self

    def set_test_paths(self, test_paths: List[Path]) -> "Report":
        self.all_test_names = [str(p) for p in test_paths]
        return self

    def preprocess_results(self) -> "Report":
        for path, matches in self.matches.items():
            if len(matches) == 0:
                continue

            # split on the node_name
            truncated_path = str(path).split(self.node_name)[1][1:]
            if truncated_path not in self.results:

                self.results[truncated_path] = []

            for match in matches:
                if match.namespace not in self.failed_tests:
                    self.all_test_names.remove(match.namespace)
                    self.failed_tests.append(match.namespace)

                self.num_issues += 1
                string_data = []
                for string in match.strings:
                    self.num_matches += 1
                    instances_data = []
                    for instance in string.instances:
                        self.num_instances += 1
                        self.has_matches = True
                        instances_data.append(
                            {
                                "Matched data": instance.matched_data,
                                "Matched length": instance.matched_length,
                                "Offset": instance.offset,
                                "XOR key": instance.xor_key,
                                "Plaintext": instance.plaintext(),
                            }
                        )
                    string_data.append(
                        {
                            "Identifier": string.identifier,
                            "Is XOR": string.is_xor(),
                            "Instances": instances_data,
                        }
                    )
                self.results[truncated_path].append(
                    {
                        "Rule": match.rule,
                        "Namespace": match.namespace,
                        "Tags": match.tags,
                        "Meta": match.meta,
                        "Strings": string_data,
                    }
                )
        return self

    def write_to_logfile(self, logfile_path: Path) -> "Report":
        results_json = json.dumps(self.results, indent=4)
        with logfile_path.open("a") as f:
            f.write(results_json)
        return self

    def truncate_testnames(self) -> "Report":
        self.passed_tests = [
            str(Path(p).name) for p in self.all_test_names if p not in self.failed_tests
        ]
        self.failed_tests = [str(Path(p).name) for p in self.failed_tests]
        return self

    def populate_template(self):

        env = Environment(
            loader=FileSystemLoader("report-formatters/html-templates")
        )
        template = env.get_template("yara-results-template.html")
        output_html = template.render(
            results=self.results,
            date=time.strftime("%Y-%m-%d %H:%M:%S"),
            node_name=self.node_name,
            has_passed_tests=bool(self.passed_tests),
            has_failed_tests=bool(self.failed_tests),
            n_passed_tests=len(self.passed_tests),
            n_failed_tests=len(self.failed_tests),
            n_issues=self.num_issues,
            n_matches=self.num_matches,
            n_instances=self.num_instances,
            passed_tests=self.all_test_names,
            failed_tests=self.failed_tests,
        )

        save_dir = self.output_dir / f"{self.node_name}-yara.html"
        with open(save_dir, "w") as f:
            f.write(output_html)

        print(f"Report for {self.node_name} saved to {save_dir}")
