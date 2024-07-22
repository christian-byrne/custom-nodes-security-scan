all_scores = "/home/c_byrne/projects/custom-nodes-security-scan/docs/scores/cumulative-scores.json"

import json
with open(all_scores, "r") as f:
    scores = json.load(f)

scores_ = []
for category in scores.values():
    score = category["raw"]
    scores_.append(float(score))

new_scores = [163.16, 149.96]

print(scores_)
# Get z-score of new scores relative to old scores
from scipy import stats

z_scores = stats.zscore(new_scores + scores_)
for _ in range(len(new_scores)):
    print(f"Z-score: {z_scores[_]}")

