"""Run text extraction in a separate, resource-limited process.

pypdf and openpyxl parse untrusted bytes, and some of their work cannot be bounded from
outside: building every font a page names, expanding a string through a font's
ToUnicode map, joining styles. The budgets in extract.py cover the cases known so far;
this module is the backstop for the rest. Each file is read by a fresh Python process
that first lowers its own limits (address space, CPU seconds, file size, open files)
and only then imports the parsers. The parent sends the bytes on stdin, reads one
small JSON reply from stdout, and kills the child when it runs past a wall-clock
timeout or writes too much. Whatever goes wrong in the child (out of memory, killed,
timed out, garbled reply) becomes an ExtractError, which read_file reports with a
pointer to download_file. A child that could not even start (an import failing, no
reply at all) is a broken deployment, not a hard file: it is logged as an error and
reported as such.

The child is started with `python -I -B -c ...` and an environment holding only what
the interpreter needs to start, so no secrets are handed to it, and it imports nothing
from the working directory. This bounds resources; it is not a sandbox against code
run through a parser bug: the child runs as the same user as the server, so such code
could read the server's memory and environment through /proc. It finds this package
(and the parent's dependencies) through the parent's import path, passed explicitly,
which works both under Vercel (where api/index.py adds src/ to sys.path) and when the
package is installed.

Concurrency: at most MAX_CHILDREN children run at once in a server process, and at most
one per caller (the person, or API token, the call is made for), so one caller's slow
files cannot hold every slot. A read waits WAIT_SECONDS at most for a slot and then
fails at once with a "busy, try again" message; once it has a slot the child gets its
whole TIMEOUT_SECONDS. With the PDF deadline in extract.py that keeps a read, and a
Google Sheet's CSV fallback after it, well inside the function's 60 seconds.

Bytecode: the host may ship no .pyc files (Vercel installs dependencies with
--no-compile and its file system is read-only), so each child would compile pypdf and
openpyxl from source, about 0.6 s a file. The first read starts a one-off process that
compiles them into a private temporary directory, and children read from there
(`-X pycache_prefix`); they still write nothing.

No fork of the threaded server (subprocess uses fork+exec without preexec_fn, which
is safe with threads) and no multiprocessing primitives (no /dev/shm on Lambda).
"""

import json
import logging
import os
import selectors
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from .extract import Extracted, ExtractError, clean_text

logger = logging.getLogger(__name__)


class ExtractBusy(ExtractError):
    """No slot came free in time; the file itself may be fine. Worth trying again."""


DEFAULT_MEMORY_MB = 768
# Wall-clock time a child may take once started, CPU seconds it may use, and how many
# may run at once in one server process (each may use up to its memory limit). A read
# waits at most WAIT_SECONDS for a free slot.
TIMEOUT_SECONDS = 15.0
CPU_SECONDS = 12
MAX_CHILDREN = 2
WAIT_SECONDS = 5.0
# Open files a child may hold. Imports need a few; extraction needs none.
_CHILD_FILES = 64
# Most of a child's stderr kept for the log when it fails without a reply.
_STDERR_KEEP = 2048
# Python escapes each character in JSON as at most 12 ASCII bytes (a pair of \\uXXXX).
_REPLY_BYTES_PER_CHAR = 12
_REPLY_OVERHEAD = 1024 * 1024

# Children running, and the callers they run for.
_slots = threading.Condition()
_running = 0
_running_for: set[str] = set()

_TOO_BIG = "file is too large or complex to extract; use download_file"
_TOO_SLOW = "file took too long to extract; use download_file"
_FAILED = "text could not be extracted; use download_file"
_BUSY = "the server is busy reading other files; try again in a few seconds"
_OWN_BUSY = "another of your files is still being read; try again in a few seconds"
_BROKEN = "text extraction is not working on this server; use download_file"
# In a child's stderr: it ran out of memory (rather than failing to start).
_OUT_OF_MEMORY = (b"MemoryError", b"Cannot allocate memory", b"out of memory")
# Packages the child imports, compiled once into the bytecode cache.
_WARM_PACKAGES = (
    __package__ or "scoped_drive_mcp",
    "pypdf",
    "openpyxl",
    "et_xmlfile",
    "defusedxml",
    "striprtf",
    "olefile",
)
_WARM_SECONDS = 60.0

# Environment variables passed to the child: only what the interpreter may need to start.
_ENV_KEEP = ("PATH", "LD_LIBRARY_PATH", "SYSTEMROOT", "TMPDIR")

# Puts the parent's import path first, then runs main(), which sets the limits before
# anything imports pypdf or openpyxl.
_BOOTSTRAP = (
    "import json, sys; "
    "sys.path[:0] = [entry for entry in json.loads(sys.argv[1]) if entry not in sys.path]; "
    f"from {__name__} import main; main()"
)
# Compiles the packages the child imports; run once with -X pycache_prefix, no -B.
_WARM = (
    "import compileall, importlib.util, json, sys\n"
    "sys.path[:0] = [entry for entry in json.loads(sys.argv[1]) if entry not in sys.path]\n"
    "for name in json.loads(sys.argv[2]):\n"
    "    try:\n"
    "        spec = importlib.util.find_spec(name)\n"
    "    except Exception:\n"
    "        continue\n"
    "    if spec is None or not spec.origin:\n"
    "        continue\n"
    "    if spec.submodule_search_locations:\n"
    "        for folder in spec.submodule_search_locations:\n"
    "            compileall.compile_dir(folder, quiet=2, workers=1)\n"
    "    else:\n"
    "        compileall.compile_file(spec.origin, quiet=2)\n"
)


# ---- parent side ----


def extract_isolated(
    data: bytes,
    kind: str,
    *,
    char_limit: int,
    memory_mb: int = DEFAULT_MEMORY_MB,
    timeout: float = TIMEOUT_SECONDS,
    caller: str | None = None,
) -> Extracted:
    """extract.extract(), run in a child process with hard limits. `caller` defaults to
    the person or token the current call is made for (see current_caller)."""
    request = {"mode": "text", "kind": kind, "char_limit": char_limit}
    reply = _run(request, data, memory_mb, timeout, caller)
    text, truncated = reply.get("text"), reply.get("truncated")
    if not isinstance(text, str) or not isinstance(truncated, bool):
        raise _garbled("reply has no text")
    return Extracted(clean_text(text[: char_limit + 1]), truncated)


def xlsx_tabs_isolated(
    data: bytes,
    *,
    char_limit: int,
    memory_mb: int = DEFAULT_MEMORY_MB,
    timeout: float = TIMEOUT_SECONDS,
    caller: str | None = None,
) -> tuple[list[tuple[str, str]], bool]:
    """extract.read_xlsx_tabs(): (tab title, text) pairs and whether text was left out."""
    request = {"mode": "tabs", "kind": "xlsx", "char_limit": char_limit}
    reply = _run(request, data, memory_mb, timeout, caller)
    tabs, truncated = reply.get("tabs"), reply.get("truncated")
    if not isinstance(tabs, list) or not isinstance(truncated, bool):
        raise _garbled("reply has no tabs")
    pairs: list[tuple[str, str]] = []
    for tab in tabs:
        if not (
            isinstance(tab, list)
            and len(tab) == 2
            and isinstance(tab[0], str)
            and isinstance(tab[1], str)
        ):
            raise _garbled("reply has a malformed tab")
        pairs.append((clean_text(tab[0]), clean_text(tab[1])))
    return pairs, truncated


def current_caller() -> str | None:
    """Whom the current call is for: the signed-in person, else the API token, else
    the person reading someone's shared files, else the tenant. None outside a call."""
    from .auth import current_actor, current_guest, current_principal

    principal = current_principal.get()
    if principal is not None:
        return f"user:{principal.email}" if principal.email else f"token:{principal.token_name}"
    for person in (current_guest.get(), current_actor.get()):
        if person:
            return f"user:{person}"
    return None


def _acquire(caller: str | None, wait: float) -> None:
    """Take a slot for `caller` within `wait` seconds, or raise ExtractBusy."""
    global _running
    deadline = time.monotonic() + wait
    with _slots:
        while _running >= MAX_CHILDREN or (caller is not None and caller in _running_for):
            left = deadline - time.monotonic()
            if left <= 0:
                own = caller is not None and caller in _running_for
                raise ExtractBusy(_OWN_BUSY if own else _BUSY)
            _slots.wait(left)
        _running += 1
        if caller is not None:
            _running_for.add(caller)


def _release(caller: str | None) -> None:
    global _running
    with _slots:
        _running -= 1
        if caller is not None:
            _running_for.discard(caller)
        _slots.notify_all()


def _garbled(why: str) -> ExtractError:
    logger.warning("text extraction child sent a bad reply: %s", why)
    return ExtractError(_FAILED)


def _run(request: dict, data: bytes, memory_mb: int, timeout: float, caller: str | None) -> dict:
    if caller is None:
        caller = current_caller()
    _warm_bytecode()
    _acquire(caller, WAIT_SECONDS)
    try:
        # The whole timeout, however long the wait for the slot was.
        reply_cap = _REPLY_BYTES_PER_CHAR * (int(request["char_limit"]) + 1) + _REPLY_OVERHEAD
        out = _spawn(json.dumps(request).encode() + b"\n" + data, memory_mb, timeout, reply_cap)
    finally:
        _release(caller)
    try:
        reply = json.loads(out)
    except ValueError as exc:
        raise _garbled("reply is not JSON") from exc
    if not isinstance(reply, dict):
        raise _garbled("reply is not an object")
    error = reply.get("error")
    if error is not None:
        # The child only sends messages written in extract.py (safe to show), but keep
        # a confused child from sending anything long or odd.
        if not isinstance(error, str) or len(error) > 300 or not error.isprintable():
            raise _garbled("reply has a malformed error")
        raise ExtractError(error)
    return reply


def _import_paths() -> list[str]:
    """The parent's import path, so the child finds the same dependencies (Vercel puts
    them in the function's directory, not in the interpreter's site-packages). Relative
    entries are made absolute against this working directory; the empty entry (the
    working directory itself) is left out."""
    package_parent = str(Path(__file__).resolve().parent.parent)
    paths = [package_parent]
    for entry in sys.path:
        if not isinstance(entry, str) or not entry:
            continue
        entry = os.path.abspath(entry)
        if entry not in paths:
            paths.append(entry)
    return paths


def _child_command(memory_mb: int) -> list[str]:
    if not sys.executable:
        raise ExtractError(_FAILED)
    command = [
        sys.executable,
        "-I",  # no PYTHON* variables, no user site-packages, no script or working directory
        "-B",  # write no .pyc files (the child may not create files); reading them is fine
    ]
    if _bytecode_dir is not None:
        command += ["-X", f"pycache_prefix={_bytecode_dir}"]
    return command + [
        "-c",
        _BOOTSTRAP,
        json.dumps(_import_paths()),
        str(memory_mb),
        str(CPU_SECONDS),
    ]


# The private bytecode cache the children read, once _warm_bytecode has made it.
_bytecode_dir: str | None = None
_warm_started = False
_warm_lock = threading.Lock()


def _warm_bytecode() -> None:
    """Once per process, compile the child's packages into a private directory in the
    background. Children started before it is done compile what is missing themselves,
    as they would without it; if it fails, nothing changes."""
    global _warm_started, _bytecode_dir
    with _warm_lock:
        if _warm_started:
            return
        _warm_started = True
        try:
            folder = tempfile.mkdtemp(prefix="scoped-drive-pycache-")  # mode 0700
        except OSError as exc:
            logger.info("no bytecode cache for text extraction (%s)", exc)
            return
        _bytecode_dir = folder
    threading.Thread(target=_compile_into, args=(folder,), daemon=True).start()


def _compile_into(folder: str) -> None:
    if not sys.executable:
        return
    command = [
        sys.executable,
        "-I",
        "-X",
        f"pycache_prefix={folder}",
        "-c",
        _WARM,
        json.dumps(_import_paths()),
        json.dumps(list(_WARM_PACKAGES)),
    ]
    try:
        subprocess.run(  # noqa: S603 (this interpreter and fixed arguments)
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_child_env(),
            timeout=_WARM_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.info("could not compile the text extraction bytecode (%s)", exc)


def _child_env() -> dict[str, str]:
    return {name: os.environ[name] for name in _ENV_KEEP if name in os.environ}


def _spawn(payload: bytes, memory_mb: int, timeout: float, reply_cap: int) -> bytes:
    """Run the child with `payload` on stdin; its stdout, or ExtractError."""
    deadline = time.monotonic() + max(timeout, 0.0)
    try:
        child = subprocess.Popen(  # noqa: S603 (this interpreter and fixed arguments)
            _child_command(memory_mb),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_child_env(),
            close_fds=True,
        )
    except OSError as exc:
        logger.warning(
            "could not start the text extraction process (%s); set EXTRACT_ISOLATION=0 "
            "where subprocesses are not allowed",
            exc,
        )
        raise ExtractError(_FAILED) from exc
    try:
        if os.name == "nt":  # pipes cannot be polled with selectors on Windows
            out, err, status = _communicate(child, payload, deadline)
        else:
            out, err, status = _pump(child, payload, deadline, reply_cap)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    if status == "timeout":
        logger.info("text extraction child timed out")
        raise ExtractError(_TOO_SLOW)
    if status == "overflow":
        logger.warning("text extraction child wrote more than %d bytes", reply_cap)
        raise ExtractError(_FAILED)
    code = child.returncode
    if code == 0 and out:
        return out
    tail = err.decode("utf-8", "replace").strip()[-500:]
    if (code is not None and code < 0) or any(sign in err for sign in _OUT_OF_MEMORY):
        # A signal is the CPU limit (or memory the kernel would not give); a MemoryError
        # it could not report is the memory limit. Both are the file's doing.
        logger.info("text extraction child failed (exit %s): %s", code, tail)
        raise ExtractError(_TOO_BIG)
    # The child always replies, even to a file it cannot read, unless it could not
    # start: an import failed, or the interpreter could not run. That is the server's
    # setup, and every file would fail the same way (stderr holds no document text).
    logger.error("text extraction child exited without a reply (exit %s): %s", code, tail)
    raise ExtractError(_BROKEN)


def _pump(
    child: subprocess.Popen, payload: bytes, deadline: float, reply_cap: int
) -> tuple[bytes, bytes, str]:
    """Write stdin and read stdout and stderr at once, until the child closes them."""
    assert child.stdin and child.stdout and child.stderr
    out = bytearray()
    err = bytearray()
    view = memoryview(payload)
    written = 0
    with selectors.DefaultSelector() as selector:
        for stream in (child.stdin, child.stdout, child.stderr):
            os.set_blocking(stream.fileno(), False)
        selector.register(child.stdin, selectors.EVENT_WRITE)
        selector.register(child.stdout, selectors.EVENT_READ)
        selector.register(child.stderr, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return bytes(out), bytes(err), "timeout"
            for key, _events in selector.select(remaining):
                stream = key.fileobj
                if stream is child.stdin:
                    try:
                        written += os.write(child.stdin.fileno(), view[written : written + 65536])
                    except BlockingIOError:
                        continue
                    except (BrokenPipeError, OSError):
                        written = len(view)  # the child stopped reading (it failed)
                    if written >= len(view):
                        selector.unregister(child.stdin)
                        child.stdin.close()
                    continue
                try:
                    chunk = os.read(stream.fileno(), 65536)  # type: ignore[union-attr]
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                if stream is child.stdout:
                    out += chunk
                    if len(out) > reply_cap:
                        return bytes(out), bytes(err), "overflow"
                else:
                    err += chunk
                    del err[:-_STDERR_KEEP]
    try:
        child.wait(max(deadline - time.monotonic(), 0.01))
    except subprocess.TimeoutExpired:
        return bytes(out), bytes(err), "timeout"
    return bytes(out), bytes(err), "done"


def _communicate(
    child: subprocess.Popen, payload: bytes, deadline: float
) -> tuple[bytes, bytes, str]:
    try:
        out, err = child.communicate(payload, timeout=max(deadline - time.monotonic(), 0.01))
    except subprocess.TimeoutExpired:
        return b"", b"", "timeout"
    return out, err, "done"


# ---- child side ----


def _set_limits(memory_bytes: int, cpu_seconds: int) -> None:
    """Lower this process's own limits. Lowering never needs privileges."""
    try:
        import resource
    except ImportError:  # Windows: only the parent's timeout applies
        return
    wanted = [
        ("RLIMIT_CPU", cpu_seconds, cpu_seconds + 1),  # SIGXCPU, then SIGKILL
        ("RLIMIT_FSIZE", 0, 0),  # create no files
        ("RLIMIT_CORE", 0, 0),
        ("RLIMIT_NOFILE", _CHILD_FILES, _CHILD_FILES),
    ]
    # Address space bounds everything the process maps; where the system does not
    # enforce it (macOS), the data segment is the next best thing.
    memory_set = False
    for name in ("RLIMIT_AS", "RLIMIT_DATA"):
        if memory_set:
            break
        memory_set = _lower(resource, name, memory_bytes, memory_bytes)
    for name, soft, hard in wanted:
        _lower(resource, name, soft, hard)


def _lower(resource, name: str, soft: int, hard: int) -> bool:
    limit = getattr(resource, name, None)
    if limit is None:
        return False
    try:
        current_soft, current_hard = resource.getrlimit(limit)
        if current_hard != resource.RLIM_INFINITY:
            hard = min(hard, current_hard)
        soft = min(soft, hard)
        resource.setrlimit(limit, (soft, hard))
        return True
    except (ValueError, OSError):
        return False


def main() -> None:
    """Child entry point: argv is (import path JSON, memory MB, CPU seconds)."""
    memory_mb, cpu_seconds = int(sys.argv[2]), int(sys.argv[3])
    _set_limits(memory_mb * 1024 * 1024, cpu_seconds)
    # Library warnings quote names from the file; nothing in the child is logged.
    logging.disable(logging.CRITICAL)
    import warnings

    warnings.simplefilter("ignore")

    raw = sys.stdin.buffer.read()
    header, _, data = raw.partition(b"\n")
    del raw
    try:
        request = json.loads(header)
        reply = _serve(request, data)
    except MemoryError:
        del data
        reply = {"error": _TOO_BIG}
    except ExtractError as exc:
        reply = {"error": str(exc)}
    except Exception:
        reply = {"error": _FAILED}
    # json escapes any surrogate the extractors missed; the parent cleans it again.
    sys.stdout.buffer.write(json.dumps(reply).encode("ascii"))
    sys.stdout.buffer.flush()


def _serve(request: dict, data: bytes) -> dict:
    from .extract import extract, read_xlsx_tabs

    char_limit = int(request["char_limit"])
    if request["mode"] == "tabs":
        tabs, truncated = read_xlsx_tabs(data, char_limit)
        return {"tabs": [list(tab) for tab in tabs], "truncated": truncated}
    result = extract(data, str(request["kind"]), char_limit=char_limit)
    return {"text": result.text, "truncated": result.truncated}
