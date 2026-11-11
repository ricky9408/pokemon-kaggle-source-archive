import sys

if sys.argv != ["-c", "V631302_DIAGNOSTIC_WORKER_V1", "worker/v631302_diagnostic_worker_v1.py"]:
    raise SystemExit(80)
if (sys.flags.isolated != 1 or sys.flags.no_site != 1 or sys.flags.ignore_environment != 1 or
        sys.flags.no_user_site != 1 or sys.flags.safe_path != 1 or
        sys.flags.dont_write_bytecode != 1 or sys.flags.utf8_mode != 1 or sys.flags.optimize != 0):
    raise SystemExit(80)
data = sys.stdin.buffer.read()
if data != b"V631DI01\x00\x00\x00\x00\x00\x00\x00\x01\x80":
    raise SystemExit(80)
sys.stdout.buffer.write(b"V631DO01\x00\x00\x00\x00\x00\x00\x00\x01\x80")
