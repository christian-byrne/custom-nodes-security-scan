log_path = "/home/c_byrne/projects/custom-nodes-security-scan/memdump.log"
import re
with open(log_path, "r") as f:
    log = f.read()
    matches = re.finditer(r"__import__", log)
    for match in list(set(matches)):
        print(log[match.start():match.start()+60])