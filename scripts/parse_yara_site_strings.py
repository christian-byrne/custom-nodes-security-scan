import os
import tempfile

path = os.path.join(
    os.path.dirname(__file__),
    "..",
    "scan",
    "yara",
    "yara-rules",
    "aa-comfy-nodes-rules",
    "dangerous-sites.yar",
)


def load_txt_file(path):
    with open(path, "r") as file:
        return file.readlines()


def parse_urls(lines):
    urls = []
    for line in lines:
        if line.strip().startswith("$site"):
            try:
                line2 = line.split('= "')[1]
                line2 = line2.split('"')[0]
                urls.append(line2)
            except:
                break

    return urls


lines = load_txt_file(path)
urls = parse_urls(lines)

with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
    f.write("\n".join(urls))
    os.system(f"cat {f.name} | clipboard")
