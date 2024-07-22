import sys
import functools

LOG_NAME = "settrace_import_scan.log"
MAX_ARG_PREVIEW = 80
LOG_ALL_IMPORTS = False

# From bandit and IOC twitter
BL_IMPORTS = [
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
    # "importlib",
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

# From Bandit
BL_CALLS = [
    "eval",
    "exec",
    "compile",
    "globals",
    "locals",
    "pickle.loads",
    "pickle.load",
    "pickle.Unpickler",
    "dill.loads",
    "dill.load",
    "dill.Unpickler",
    "shelve.open",
    "shelve.DbfilenameShelf",
    "jsonpickle.decode",
    "jsonpickle.unpickler.decode",
    "jsonpickle.unpickler.Unpickler",
    "pandas.read_pickle",
    "marshal.load",
    "marshal.loads",
    "Crypto.Hash.MD2.new",
    "Crypto.Hash.MD4.new",
    "Crypto.Hash.MD5.new",
    "Crypto.Hash.SHA.new",
    "Cryptodome.Hash.MD2.new",
    "Cryptodome.Hash.MD4.new",
    "Cryptodome.Hash.MD5.new",
    "Cryptodome.Hash.SHA.new",
    "cryptography.hazmat.primitives.hashes.MD5",
    "cryptography.hazmat.primitives.hashes.SHA1",
    "Crypto.Cipher.ARC2.new",
    "Crypto.Cipher.ARC4.new",
    "Crypto.Cipher.Blowfish.new",
    "Crypto.Cipher.DES.new",
    "Crypto.Cipher.XOR.new",
    "Cryptodome.Cipher.ARC2.new",
    "Cryptodome.Cipher.ARC4.new",
    "Cryptodome.Cipher.Blowfish.new",
    "Cryptodome.Cipher.DES.new",
    "Cryptodome.Cipher.XOR.new",
    "cryptography.hazmat.primitives.ciphers.algorithms.ARC4",
    "cryptography.hazmat.primitives.ciphers.algorithms.Blowfish",
    "cryptography.hazmat.primitives.ciphers.algorithms.IDEA",
    "cryptography.hazmat.primitives.ciphers.modes.ECB",
    "tempfile.mktemp",
    "eval",
    "django.utils.safestring.mark_safe",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "urllib.request.URLopener",
    "urllib.request.FancyURLopener",
    "six.moves.urllib.request.urlopen",
    "six.moves.urllib.request.urlretrieve",
    "six.moves.urllib.request.URLopener",
    "six.moves.urllib.request.FancyURLopener",
    "random.Random",
    "random.random",
    "random.randrange",
    "random.randint",
    "random.choice",
    "random.choices",
    "random.uniform",
    "random.triangular",
    "random.randbytes",
    "telnetlib.Telnet",
    "xml.etree.cElementTree.parse",
    "xml.etree.cElementTree.iterparse",
    "xml.etree.cElementTree.fromstring",
    "xml.etree.cElementTree.XMLParser",
    "xml.etree.ElementTree.parse",
    "xml.etree.ElementTree.iterparse",
    "xml.etree.ElementTree.fromstring",
    "xml.etree.ElementTree.XMLParser",
    "xml.sax.expatreader.create_parser",
    "xml.dom.expatbuilder.parse",
    "xml.dom.expatbuilder.parseString",
    "xml.sax.parse",
    "xml.sax.parseString",
    "xml.sax.make_parser",
    "xml.dom.minidom.parse",
    "xml.dom.minidom.parseString",
    "xml.dom.pulldom.parse",
    "xml.dom.pulldom.parseString",
    "lxml.etree.parse",
    "lxml.etree.fromstring",
    "lxml.etree.RestrictedElement",
    "lxml.etree.GlobalParserTLS",
    "lxml.etree.getDefaultParser",
    "lxml.etree.check_docinfo",
    "ftplib.FTP",
    "ssl._create_unverified_context",
    "x.import",
]

BL_ARGS = [
    "https://",
    "ws://",
    "wss://",
    "http://",
    "ftp://",
    "sftp://",
    "ssh://",
    "telnet://",
    "smtp://",
    "pop3://",
    "imap://",
    "ldap://",
    "ldaps://",
]


def log_(message):
    with open(LOG_NAME, "a") as f:
        f.write(message + "\n")


all_imports = set()
import_violations = set()
arg_violoations = set()
call_violations = set()


def handle_exceptions(logger=None):
    def decorator(func):
        @functools.wraps(func)  # Preserve function metadata
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if logger:
                    logger.exception(f"Exception occurred in '{func.__name__}': {e}")
                else:
                    pass
                    # print(f"Exception occurred: {e}")

        return wrapper

    return decorator


@handle_exceptions()
def scan_args(arg, frame):
    global arg_violoations
    for bl_arg in BL_ARGS:
        if bl_arg in repr(arg):
            preview = repr(arg)[
                max(0, repr(arg).index(bl_arg) - 5) : min(
                    len(repr(arg)), repr(arg).index(bl_arg) + MAX_ARG_PREVIEW
                )
            ]
            arg_length = len(repr(arg))
            context = f"Function '{frame.f_code.co_name}'\n\tCalled with arg containing '{bl_arg}'\n\tPreview: {preview}\n\t(full arg length: {arg_length})\n\tLocation: {frame.f_code.co_filename}:{frame.f_lineno}"
            arg_violoations.add(context)


@handle_exceptions()
def scan_calls(frame):
    global call_violations
    code = frame.f_code
    for bl_func_name in BL_CALLS:
        if bl_func_name == code.co_name:
            import_violations.add(repr(code.co_name))


@handle_exceptions()
def scan_builtin_import_calls(frame):
    """https://github.com/python/cpython/blob/69f2dc5c06e62b4a9eb4da8f0cd456cc09b998ed/Lib/importlib/_bootstrap.py#L1454"""
    global import_violations
    global all_imports
    function_vars = frame.f_locals
    module_var = function_vars["module"]
    if module_var:
        all_imports.add(repr(module_var.__name__))
        for bl_import_name in BL_IMPORTS:
            if bl_import_name in module_var.__name__:
                import_violations.add(repr(module_var))


@handle_exceptions()
def scan_calc_package_calls(frame):
    """https://github.com/python/cpython/blob/69f2dc5c06e62b4a9eb4da8f0cd456cc09b998ed/Lib/importlib/_bootstrap.py#L1427"""
    global import_violations
    global all_imports
    function_vars = frame.f_locals
    package_var = function_vars["package"]
    if package_var:
        all_imports.add(repr(package_var.__name__))
        for bl_import_name in BL_IMPORTS:
            if bl_import_name in package_var.__name__:
                import_violations.add(repr(package_var))


@handle_exceptions()
def scan_import_frame_stripping(frame):
    """https://github.com/python/cpython/blob/69f2dc5c06e62b4a9eb4da8f0cd456cc09b998ed/Lib/importlib/_bootstrap.py#L480"""
    if frame.f_code.co_name == "_call_with_frames_removed":
        args_var = frame.f_locals["args"]
        f_var = frame.f_locals["f"]
        if f_var == __import__:
            for import_arg in args_var:
                all_imports.add(repr(import_arg))
                for bl_import_name in BL_IMPORTS:
                    if bl_import_name in repr(import_arg):
                        import_violations.add(repr(args_var))


@handle_exceptions()
def scan_import_fromlist(frame):
    """https://github.com/python/cpython/blob/69f2dc5c06e62b4a9eb4da8f0cd456cc09b998ed/Lib/importlib/_bootstrap.py#L1390"""
    if frame.f_code.co_name == "_handle_fromlist":
        module_arg = frame.f_locals["module"]
        if module_arg:
            all_imports.add(repr(module_arg))
            for bl_import_name in BL_IMPORTS:
                if bl_import_name in repr(module_arg):
                    import_violations.add(repr(module_arg))

        fromlist_arg = frame.f_locals["fromlist"]
        if fromlist_arg:
            for fromlist_item in fromlist_arg:
                all_imports.add(repr(fromlist_item))
                for bl_import_name in BL_IMPORTS:
                    if bl_import_name in repr(fromlist_item):
                        import_violations.add(repr(fromlist_item))


# ---------------------------------------------------------


def trace_calls(frame, event, arg):
    scan_args(arg, frame)
    if event == "call" or event == "return":
        scan_calls(frame)
        scan_builtin_import_calls(frame)
        scan_calc_package_calls(frame)
        scan_import_frame_stripping(frame)
        scan_import_fromlist(frame)

    return trace_calls


sys.settrace(trace_calls)
try:
    from malware_samples import ComfyUI_LLMVISION
except Exception as e:
    print("\n\n\nMain Terminated:")
    print(e)
sys.settrace(None)


with open(LOG_NAME, "w") as f:
    f.write("")

log_("\nImport violations:\n")
for item in import_violations:
    log_(item.strip("'"))

log_("\nArgument violations:\n")
for item in arg_violoations:
    log_(item.strip("'"))

log_("\nCall violations:\n")
for item in call_violations:
    log_(item.strip("'"))

if LOG_ALL_IMPORTS:
    log_("\nAll imports:")
    for item in all_imports:
        log_(item.strip("'"))
