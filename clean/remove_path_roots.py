import os

this_path = os.path.dirname(os.path.abspath(__file__))
html_path = os.path.join(this_path, "..", "docs")
base_path = "/home/c_byrne/tools/sd/sd-interfaces/ComfyUI/custom_nodes/"
for root, dirs, files in os.walk(html_path):
    for file in files:
        if file.endswith(".html"):
            with open(os.path.join(root, file), "r") as f:
                html = f.read()
            html = html.replace(f'href="{base_path}', 'href="')
            while base_path in html:
                html = html.replace(base_path, "")

            with open(os.path.join(root, file), "w") as f:
                f.write(html)

print("Done")
