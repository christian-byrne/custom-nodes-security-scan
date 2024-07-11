import os
import sys

dir_ = os.path.join(os.path.dirname(__file__), "_posts")

for filename in os.listdir(dir_):
    if filename.endswith(".html"):
        with open(os.path.join(dir_, filename), "r") as file:
            data = file.read()
        if not data.startswith("---"):
            with open(os.path.join(dir_, filename), "w") as file:
                file.write(
                    f"---\nlayout: front\ntitle: {filename.replace('.html', '')}\n---\n"
                    + data
                )

print("Done")