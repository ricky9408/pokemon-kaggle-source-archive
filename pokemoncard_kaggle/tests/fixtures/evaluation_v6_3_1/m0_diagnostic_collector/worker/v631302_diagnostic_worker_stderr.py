import sys

data = sys.stdin.buffer.read()
if data != b"V631DI01\x00\x00\x00\x00\x00\x00\x00\x01\x80":
    raise SystemExit(80)
sys.stdout.buffer.write(b"V631DO01\x00\x00\x00\x00\x00\x00\x00\x01\x80")
sys.stderr.write("unexpected stderr")
