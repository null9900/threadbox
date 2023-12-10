import functools

def sandbox_ps():
    write_to_file("sandbox_ps");

def PERM(permission, options):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                write_to_file(permission,options);
                #if permission == "listen_socket":
                #    write_to_file("listen_socket",options);
                #if permission == "bind_socket":
                #    write_to_file("bind_socket",options);
                #elif permission == "disable_all":
                #    write_to_file("disable_all");
                #elif permission == "fork":
                #    write_to_file("fork");
                #elif permission == "ioctl":
                #    write_to_file("ioctl",options)
                return fn(*args, **kwargs)
            finally:
                write_to_file("remove_sandbox");
        return wrapper
    return decorator

def write_to_file(file,data=1):
    f = open("/sys/kernel/security/funcsandbox/"+file, "a")
    f.write(str(data))
    f.close()

