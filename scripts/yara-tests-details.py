import os
from pathlib import Path

root_dir = "yara-rules"
count_lines = 0
print("> | Source | Test Name |")
print("> |---------|-----------|")
count = 0
for root, dirs, files in os.walk(root_dir):
    for file in files:
        if (
            file.endswith(".yar")
            or file.endswith(".yara")
            or file.endswith(".rule")
            or file.endswith(".rules")
        ):

            count += 1
            with open(os.path.join(root, file), "r") as f:
                count_lines += len(f.readlines())
                subpath = os.path.join(root, file).split(root_dir)[1].split(os.sep)[1]
                print(f"> | {subpath} | {file} |")


print(f"Total files: {count}")
print(f"Total lines: {count_lines}")
