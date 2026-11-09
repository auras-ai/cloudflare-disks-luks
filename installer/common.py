"""Bounded subprocesses, private durable files, and secret-free diagnostics."""
import getpass
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import warnings


class SetupError(Exception):
    """An actionable diagnostic that never contains credential values."""


def require(condition, message):
    if not condition:
        raise SetupError(message)


def run(args, *, data=None, check=True, timeout=120, env=None):
    """Arguments contain no secrets. Child output is private until explicitly selected."""
    try:
        result = subprocess.run([str(a) for a in args], input=data, capture_output=True,
                                timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SetupError(f"{Path(str(args[0])).name}: command unavailable or timed out") from error
    if check and result.returncode:
        # Do not echo argv, stdout or stderr: tools may reproduce credentials.
        raise SetupError(f"{Path(str(args[0])).name}: operation failed (exit {result.returncode})")
    return result


def no_symlinks(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, "Use a normalized absolute path")
    for component in [*reversed(path.parents), path]:
        require(not component.is_symlink(), "Symlinks are not allowed in setup/storage paths")
    return path


def private_dir(path, *, uid=None, gid=None):
    path = no_symlinks(path)
    uid = os.geteuid() if uid is None else uid
    gid = os.getegid() if gid is None else gid
    if not path.exists():
        path.mkdir(mode=0o700)
        os.chown(path, uid, gid)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid
            and stat.S_IMODE(info.st_mode) == 0o700, f"Expected private owned directory: {path}")
    return path


def read_private(path, *, uid=None, limit=65536):
    path = no_symlinks(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == (os.geteuid() if uid is None else uid)
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= limit,
                "Expected a private, owned, single-link regular file")
        data = source.read(limit + 1)
        require(len(data) <= limit, "Private input exceeds size limit")
        return data


def atomic_write(path, data, *, replace=False, mode=0o600, uid=None, gid=None):
    path = no_symlinks(path)
    if isinstance(data, str):
        data = data.encode()
    require(replace or not path.exists(), f"Refusing to overwrite {path}")
    if path.exists():
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "Refusing to replace a symlink, hardlink or special file")
    fd, temporary = tempfile.mkstemp(prefix='.setup-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            if uid is not None:
                os.fchown(output.fileno(), uid, gid)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
            os.unlink(temporary)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value, **options):
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + '\n', **options)


def hidden(prompt, *, minimum=1, maximum=1024, confirm=False):
    # getpass otherwise falls back to echoed stdin on some systems.
    try:
        with open('/dev/tty', 'r+') as tty:
            require(os.isatty(tty.fileno()), "Secret entry needs an interactive terminal")
    except OSError as error:
        raise SetupError("Run setup in an interactive terminal for hidden secret prompts") from error
    def read_hidden(label):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                return getpass.getpass(label)
        except getpass.GetPassWarning:
            raise SetupError('Terminal cannot disable echo; secret entry cancelled') from None

    value = read_hidden(prompt + ': ')
    require(minimum <= len(value.encode()) <= maximum
            and not any(ord(c) < 32 or ord(c) == 127 for c in value),
            f"Secret must be {minimum}–{maximum} bytes without control characters")
    if confirm:
        require(value == read_hidden('Confirm ' + prompt.lower() + ': '), "The two entries differ")
    return value


def install_same(path, data, *, mode=0o600, uid=None, gid=None):
    """Resume an owned installation; never silently replace a different file."""
    path = no_symlinks(path)
    data = data.encode() if isinstance(data, str) else data
    if path.exists():
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == (os.geteuid() if uid is None else uid)
                and stat.S_IMODE(info.st_mode) == mode and path.read_bytes() == data,
                f"Existing file differs from this installation: {path}")
    else:
        atomic_write(path, data, mode=mode, uid=uid, gid=gid)


def confirm(prompt, expected='yes'):
    require(input(f'{prompt}\nType {expected!r} to continue: ').strip() == expected,
            'Cancelled; recorded setup progress is retained')
