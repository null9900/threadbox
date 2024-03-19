import functools

def sandbox_ps():
    write_to_file("sandbox_ps");

def PERM(promises):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                write_to_file("promises",promises);
                return fn(*args, **kwargs)
            finally:
                write_to_file("remove_sandbox");
        return wrapper
    return decorator

def write_to_file(file,data=1):
    f = open("/sys/kernel/security/funcsandbox/"+file, "a")
    f.write(str(data))
    f.close()

