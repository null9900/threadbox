import functools
import threading
import concurrent.futures
import prctl

def sandbox_ps():
    send_to_lsm("sandbox_ps", "");

def permissions(promises):
    send_to_lsm("promises", promises);

def run_function(fn, promises,args):
    send_to_lsm("promises", promises);
    return fn(*args)

def sandbox_function(promises):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_function, fn, promises, args)
                    return future.result()
            except:
                print(err)
        return wrapper
    return decorator

def send_to_lsm(file, data):
    prctl.set_no_new_privs(1)
    f = open("/sys/kernel/security/funcsandbox/"+file, "a")
    if(data==""):
        data = " "
    f.write(str(data))
    f.close()

__all__ = [ "sandbox_ps", "sandbox_function", "permissions" ]
