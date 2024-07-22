"""

> | Package Name | Test ID |
> |---------|-----------|
> | telnetlib   | B401 |
> | ftplib   | B402 |
> | httpoxy   | B412 |
> | pycrypto   | B413 |
> | pyghmi   | B415 |
> | paramiko   | B601 |
> | subprocess   | B602 |
> | pip   | B816 |
> | tarfile   | B817 |
> | zipfile   | B818 |
> | importlib   | B819 |
> | imp   | B820 |
> | pkgutil   | B821 |
> | runpy   | B822 |
> | ctpyes   | B823 |
> | os.system   | B824 |
> | pty   | B825 |
> | requests.urlib   | B826 |
> | http.server   | B827 |
> | pickle   | B403 |
> | subprocess   | B404 |
> | xml.etree   | B405 |
> | xml.sax   | B406 |
> | xml.expat   | B407 |
> | xml.minidom   | B408 |
> | xml.pulldom   | B409 |
> | lxml   | B410 |
> | xmlrpclib   | B411 |

"""

import sys

log_filename = "settrace-log-filtered.log"
with open(log_filename, "w") as f:
    f.write("")


def write_to_log(message):
    with open(log_filename, "a") as f:
        f.write(message + "\n")


tracelog = set()
all_imports = set()
import_violations = set()

blacklisted_imports = [
    "crypto",
    "Crypto",
    "telnetlib",
    "ftplib",
    "httpoxy",
    "pycrypto",
    "pyghmi",
    "paramiko",
    "pip",
    "tarfile",
    "zipfile",
    "importlib",
    "imp",
    "pkgutil",
    "runpy",
    "ctypes",
    "os.system",
    "os.popen",
    "os.pidfd_open",
    "pty",
    "requests.urlib",
    "http.server",
    "pickle",
    "subprocess",
    "xml.etree",
    "xml.sax",
    "xml.expat",
    "xml.minidom",
    "xml.pulldom",
    "lxml",
    "xmlrpclib",
    "requests",
    "cryptography",
    "json.scanner",
    "http.cookiejar",
    "sys.modules",
    # "http", 
    # "socket",
    "urllib3",
    "email",
]
blacklisted_functions = [eval, exec, compile, globals, locals]
blacklisted_args = [
    "importlib",
    "sys.modules",
    "os.system",
    "subprocess",
    "exec",
    "eval",
    "compile",
]
blacklisted_args_refs = [__builtins__, __import__, eval, exec, compile, globals, locals]


def trace_calls(frame, event, arg):
    if event == "call":
        try:
            code = frame.f_code
            func_args = frame.f_locals
            func_name = code.co_name
            func_locals = frame.f_locals
            if "args" in func_args:
                if repr(func_args["args"]).lower() in blacklisted_imports:
                    tracelog.add(repr(func_args["args"]))
                if "f" in func_args:
                    fn = func_args["f"]
                    for f in blacklisted_functions:
                        if fn == f:
                            tracelog.add(repr(func_args["args"]))
                            break
                    if fn == __import__:
                        for import_arg in func_args["args"]:
                            all_imports.add(repr(import_arg))

                            if import_arg in blacklisted_imports or repr(import_arg).split(".")[0] in blacklisted_imports:
                                import_violations.add(repr(import_arg))

                if func_args["args"] in blacklisted_args:
                    tracelog.add(repr(func_args["args"]))
                else:
                    for ref in blacklisted_args_refs:
                        if func_args["args"] == ref:
                            tracelog.add(repr(func_args["args"]))
                            break
        except:
            pass

    elif event == "return":
        try:
            if arg != None:
                added = False
                if repr(arg).lower() in blacklisted_imports:
                    tracelog.add(repr(arg))
                    added = True
                if not added:
                    for f in blacklisted_functions:
                        if arg == f:
                            tracelog.add(repr(arg))
                            added = True
                            break
                if not added:
                    for arg in blacklisted_args:
                        if arg == arg:
                            tracelog.add(repr(arg))
                            added = True
                            break
                if not added:
                    for ref in blacklisted_args_refs:
                        if arg == ref:
                            tracelog.add(repr(arg))
                            added = True
                            break
        except:
            pass

    return trace_calls


sys.settrace(trace_calls)
try:
    from malware_samples import ComfyUI_LLMVISION
except Exception as e:
    print(e)
sys.settrace(None)

for item in tracelog:
    write_to_log(item)

write_to_log("\nImport violations:")
for item in import_violations:
    write_to_log(item.strip("'"))

write_to_log("\nAll imports:")
for item in all_imports:
    write_to_log(item.strip("'"))
