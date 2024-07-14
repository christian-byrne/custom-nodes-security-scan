"""Arbitrary scores just for exploratory purposes"""

import json

from scipy import stats
import matplotlib.pyplot as plt

from utils.config import Config
from utils.log import Logger

from typing import List, Dict

logger = Logger(__name__, Config()["log_level"])()


class ScoreCalc:
    def __init__(self):
        self.config = Config()
        self.yara_scores = self.load_scores("yara")
        self.bandit_scores = self.load_scores("bandit")
        self.scores = {}

    def __call__(self):
        self.calculate_raw_scores()
        self.calculate_z_scores()
        self.log_scores()
        self.scatter_plot()
        return self

    def scatter_plot(self):
        scores = [x["raw"] for x in self.scores.values()]

        plt.scatter(range(len(scores)), scores)
        out_dir = (
            self.config.get_proj_root() / self.config["reports_dirname"] / "scores"
        )
        plt.title("Raw Scores")
        plt.savefig(out_dir / "raw_scores.png")

        slope, intercept, r_value, p_value, std_err = stats.linregress(
            range(len(scores)), scores
        )
        residuals = [scores[i] - (slope * i + intercept) for i in range(len(scores))]
        plt.scatter(range(len(scores)), residuals, color="red")
        plt.title("Raw Scores and Residuals")
        plt.savefig(out_dir / "raw_scores_residuals.png")

        logger.info(f"Saved scatter plots to {out_dir}")

    def calculate_raw_scores(self):
        scores_ct = len(set([*self.yara_scores.keys(), *self.bandit_scores.keys()]))
        logger.info(f"Calculating cumulative scores for {scores_ct} packages")

        for node_name, scores in self.yara_scores.items():
            if node_name not in self.scores:
                self.scores[node_name] = {
                    "raw": 0,
                }

            score = 0
            score += scores["num_issues"] * 32
            score += scores["num_matched_patterns"] * 8
            score += scores["num_match_instances"] * 0.04
            self.scores[node_name]["raw"] += score

        for node_name, score in self.bandit_scores.items():
            if node_name not in self.scores:
                self.scores[node_name] = {
                    "raw": 0,
                }
            self.scores[node_name]["raw"] += score["score"]

        raw_scores = [x["raw"] for x in self.scores.values()]
        logger.debug(f"Finished calculating raw scores: {self.summary(raw_scores)}")

    def summary(self, scores: List[float]):
        x = stats.describe(scores)
        stdv = x.variance**0.5
        median = scores[int(len(scores) / 2)]
        return ", ".join(
            [
                f"Min: {x.minmax[0]}",
                f"Q1: {scores[int(len(scores) * 0.25)]}",
                f"Median: {median:.2f}",
                f"Q3: {scores[int(len(scores) * 0.75)]}",
                f"Max: {x.minmax[1]}",
                f"Mean: {x.mean:.2f}",
                f"Std Dev: {stdv:.2f}",
            ]
        )

    def calculate_z_scores(self):
        logger.info("Calculating z-scores")
        scores = [x["raw"] for x in self.scores.values()]
        z_scores = stats.zscore(scores)
        for i, node_name in enumerate(self.scores):
            self.scores[node_name]["z_score"] = z_scores[i]

    def get_scores_path(self, test_category: str):
        return (
            self.config.get_proj_root()
            / self.config["reports_dirname"]
            / "scores"
            / f"{test_category}-scores.json"
        )

    def log_scores(self):
        log_path = self.get_scores_path("cumulative")
        logger.info(f"Saving cumulative scores to {log_path}")
        with open(
            log_path,
            "w",
        ) as f:
            json.dump(self.scores, f, indent=4)

    def load_scores(self, test_category: str):
        path = self.get_scores_path(test_category)
        logger.debug(f"Loading {test_category} scores from {path}")
        with open(path, "r") as f:
            return json.load(f)
