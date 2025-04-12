import functools
import threading
import concurrent.futures
import prctl

def sandbox_ps():
    send_to_lsm("sandbox_ps", "", False, False);

def permissions(promises, debug=False, learning_mode=False):
    promises = check_alias(promises);
    send_to_lsm("promises", promises, debug, learning_mode);

def run_function(fn, promises, debug, learning_mode, args):
    promises = check_alias(promises);
    send_to_lsm("promises", promises, debug, learning_mode);
    return fn(*args)

def sandbox_function(promises, debug=False, learning_mode=False):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_function, fn, promises, debug, learning_mode, args)
                    return future.result()
            except Exception as err:
                handle_err(err)
        return wrapper
    return decorator

def handle_err(err):
    print(err)

def check_alias(promises):
    promises = promises.replace("gui", "unix");
    promises = promises.replace("ipc", "unix");
    return promises;

def send_to_lsm(file, data, debug, learning_mode):
    prctl.set_no_new_privs(1)
    f = open("/sys/kernel/security/funcsandbox/"+file, "a")
    d = open("/sys/kernel/security/funcsandbox/debug", "a")
    l = open("/sys/kernel/security/funcsandbox/learning_mode", "a")
    if data == "":
        data = " "
    f.write(str(data))
    if debug:
        d.write(str(debug));
    if learning_mode:
        l.write("1");
    f.close()
    d.close()
    l.close()

__all__ = [ "sandbox_ps", "sandbox_function", "permissions" ]
