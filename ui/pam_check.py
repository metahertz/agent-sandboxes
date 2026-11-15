#!/usr/bin/env python3
"""Check a password with PAM, for the web UI's password sign-in.

stdin: <user> NUL <password>; argv[1]: the client's address (PAM_RHOST, for
the auth log). Exit 0: accepted; 1: refused; 2: PAM couldn't check (message
on stderr).

Runs as the UI's user, and only checks that user's own password: pam_unix
then asks its setgid helper (unix_chkpwd), which a NoNewPrivileges process
can't run. So the UI starts this through the user's systemd instance
(systemd-run --user --pipe), outside its service. PAM service: agent-sandboxes
(/etc/pam.d/agent-sandboxes, or PAM's "other" when that isn't installed).
"""
import ctypes
import ctypes.util
import pwd
import os
import sys

SERVICE = "agent-sandboxes"
PAM_SUCCESS, PAM_AUTH_ERR, PAM_USER_UNKNOWN, PAM_MAXTRIES = 0, 7, 10, 11
PAM_ACCT_EXPIRED, PAM_NEW_AUTHTOK_REQD, PAM_PERM_DENIED = 13, 12, 6
PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON = 1, 2
PAM_RHOST = 4
REFUSED = {PAM_AUTH_ERR, PAM_USER_UNKNOWN, PAM_MAXTRIES, PAM_ACCT_EXPIRED, PAM_PERM_DENIED}


class PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]


CONV = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(PamMessage)),
                        ctypes.POINTER(ctypes.POINTER(PamResponse)), ctypes.c_void_p)


class PamConv(ctypes.Structure):
    _fields_ = [("conv", CONV), ("appdata_ptr", ctypes.c_void_p)]


def main() -> int:
    data = sys.stdin.buffer.read(4096)
    user, sep, password = data.partition(b"\0")
    if not sep or user.decode(errors="replace") != pwd.getpwuid(os.getuid()).pw_name:
        return 1          # only this user's own password, ever
    libpam = ctypes.CDLL(ctypes.util.find_library("pam") or "libpam.so.0")
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    libc.calloc.restype = ctypes.c_void_p
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]
    libpam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(PamConv),
                                 ctypes.POINTER(ctypes.c_void_p)]
    libpam.pam_set_item.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
    libpam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpam.pam_strerror.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpam.pam_strerror.restype = ctypes.c_char_p

    @CONV
    def conv(n, msgs, resp, _):
        # PAM frees the responses (and their strings): allocate them with libc
        arr = ctypes.cast(libc.calloc(n, ctypes.sizeof(PamResponse)), ctypes.POINTER(PamResponse))
        if not arr:
            return 5      # PAM_BUF_ERR
        for i in range(n):
            style = msgs[i].contents.msg_style
            if style == PAM_PROMPT_ECHO_OFF:
                arr[i].resp = libc.strdup(password)
            elif style == PAM_PROMPT_ECHO_ON:
                arr[i].resp = libc.strdup(user)
        resp[0] = arr
        return PAM_SUCCESS

    handle = ctypes.c_void_p()
    rc = libpam.pam_start(SERVICE.encode(), user, ctypes.byref(PamConv(conv, None)), ctypes.byref(handle))
    if rc != PAM_SUCCESS:
        print(f"pam_start: error {rc}", file=sys.stderr)
        return 2
    if len(sys.argv) > 1:
        libpam.pam_set_item(handle, PAM_RHOST, sys.argv[1].encode())
    rc = libpam.pam_authenticate(handle, 0)
    if rc == PAM_SUCCESS:
        rc = libpam.pam_acct_mgmt(handle, 0)
        if rc == PAM_NEW_AUTHTOK_REQD:     # an expired password: change it on the host first
            print("the password has expired: change it on the host (passwd)", file=sys.stderr)
            libpam.pam_end(handle, rc)
            return 1
    msg = libpam.pam_strerror(handle, rc).decode(errors="replace")
    libpam.pam_end(handle, rc)
    if rc == PAM_SUCCESS:
        return 0
    if rc in REFUSED:
        return 1
    print(f"PAM: {msg} (error {rc})", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
