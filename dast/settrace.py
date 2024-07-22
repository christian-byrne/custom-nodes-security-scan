import sys

log_filename = "debug_scanning.log"
with open(log_filename, "w") as f:
    f.write("")
def write_to_log(message):
    with open(log_filename, "a") as f:
        f.write(message + "\n")

memdump = set()

def trace_calls(frame, event, arg):
    if event == 'call':
        try:
            code = frame.f_code
            func_name = code.co_name
            func_args = frame.f_locals
            memdump.add(repr(func_name))
            memdump.add(repr(func_args))
            memdump.add(repr(frame.f_globals))
        except:
            pass
    elif event == 'return':
        try:
            memdump.add(repr(arg))
            memdump.add(repr(frame.f_code.co_name))
        except:
            pass
    return trace_calls


sys.settrace(trace_calls)
try:
    import applebotz
except Exception as e:
    print(e)
sys.settrace(None)

for item in memdump:
    if "discord" in item:
        print(item)
    write_to_log(item)


