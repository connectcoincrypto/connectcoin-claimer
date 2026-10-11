"""Hermetic real-pipe protocol tests. Never resolves names or opens a connection."""
import argparse
import json
import queue
import subprocess
import threading


START = b'{"type":"start","protocol":4,"options":{"connectionsPerSecond":800,"concurrency":800}}'
SHUTDOWN = b'{"type":"shutdown"}\n'
LIMIT = 16384


def launch(binary):
    return subprocess.Popen([binary, '--service'], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def batch(binary, data, accepted):
    child = launch(binary)
    try:
        stdout, stderr = child.communicate(data, timeout=15)
        frames = [json.loads(line) for line in stdout.splitlines()]
        require(not stderr, 'Unexpected protocol stderr')
        if accepted:
            require(child.returncode == 0 and len(frames) == 1 and
                    frames[0]['type'] == 'ready' and frames[0]['protocol'] == 4,
                    'Valid batch failed or emitted an extra frame')
        else:
            require(child.returncode != 0 and frames and frames[-1]['type'] == 'error',
                    'Malformed frame did not fail closed')
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def interactive(binary):
    child = launch(binary)
    lines = queue.Queue()

    def read():
        try:
            for line in child.stdout:
                lines.put(line)
        finally:
            lines.put(None)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        # An open pipe with a partial frame must wait; it must not require EOF
        # or a full internal I/O buffer to emit ready once newline arrives.
        child.stdin.write(START[:17])
        child.stdin.flush()
        try:
            value = lines.get(timeout=0.1)
        except queue.Empty:
            pass
        else:
            raise AssertionError(f'Partial frame produced output: {value!r}')
        child.stdin.write(START[17:] + b'\n')
        child.stdin.flush()
        frame = json.loads(lines.get(timeout=10))
        require(frame['type'] == 'ready' and frame['protocol'] == 4,
                'Ready was not flushed on a still-open pipe')
        for number in range(1, 65):
            child.stdin.write(json.dumps({'type': 'cancel', 'id': number}).encode() + b'\n')
        child.stdin.write(SHUTDOWN[:8])
        child.stdin.flush()
        require(child.poll() is None, 'Service stopped before complete shutdown frame')
        child.stdin.write(SHUTDOWN[8:])
        child.stdin.flush()
        # Shutdown must not wait for stdin EOF, and must flush every response.
        require(child.wait(timeout=10) == 0, 'Interactive shutdown failed')
        require(lines.get(timeout=5) is None, 'Unexpected output or missing EOF')
        require(not child.stderr.read(), 'Unexpected stderr')
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stdin.close()
        reader.join(timeout=5)
        child.stdout.close()
        child.stderr.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    binary = parser.parse_args().binary
    interactive(binary)
    batch(binary, START + b'\n' + SHUTDOWN, True)
    batch(binary, START + b'\r\n' + SHUTDOWN, True)
    batch(binary, START + b'\n', True)  # Clean EOF gracefully closes an idle service.
    batch(binary, START + b' ' * (LIMIT - len(START) - 1) + b'\n' + SHUTDOWN, True)
    batch(binary, START + b' ' * (LIMIT - len(START)) + b'\n', False)
    batch(binary, START, False)
    batch(binary, START + b'\n' + SHUTDOWN[:-1], False)
    batch(binary, START.replace(b'"protocol":4', b'"protocol":4,"protocol":4') + b'\n', False)
    batch(binary, START + b'\x00\n', False)
    batch(binary, START + b'\n' + b'{"type":"shutdown","extra":true}\n', False)
    # Multiple buffered commands preserve their boundaries and order.
    cancels = b''.join(json.dumps({'type': 'cancel', 'id': n}).encode() + b'\n'
                       for n in range(1, 257))
    batch(binary, START + b'\n' + cancels + SHUTDOWN, True)
    print('Real-pipe framing, flush, limits, EOF and shutdown tests passed')


if __name__ == '__main__':
    main()
