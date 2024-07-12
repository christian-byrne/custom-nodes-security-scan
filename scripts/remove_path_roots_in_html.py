import os
import sys

base_path = sys.argv[1]
if not os.path.isdir(base_path):
    raise FileNotFoundError(f"(base_path) Could not find directory at {base_path}")

html_dir = sys.argv[2]
if not os.path.isdir(html_dir):
    raise FileNotFoundError(f"(html_dir) Could not find directory at {html_dir}")

for root, dirs, files in os.walk(html_dir):
    for file in files:
        if file.endswith(".html"):
            with open(os.path.join(root, file), "r") as f:
                html = f.read()
            html = html.replace(f'href="{base_path}', 'href="')
            while base_path in html:
                html = html.replace(base_path, "")

            with open(os.path.join(root, file), "w") as f:
                f.write(html)

print(f"{__file__} finished removing base_path from html files in {html_dir}")
