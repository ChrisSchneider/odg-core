import asyncio
import datetime
import json
import logging
import os
import tracemalloc

logger = logging.getLogger(__name__)

# Set TRACEMALLOC_DIR to enable; drop a JSON file at $TRACEMALLOC_DIR/active to start tracing.
# Example: {"nframes": 15}
# Touch $TRACEMALLOC_DIR/trigger to request a snapshot.
_DIR = os.environ.get('TRACEMALLOC_DIR')
is_enabled = _DIR is not None
_ACTIVE_FILE = os.path.join(_DIR, 'active') if _DIR else None
_TRIGGER_FILE = os.path.join(_DIR, 'trigger') if _DIR else None

_DEFAULT_NFRAMES = 10  # stack frames captured per allocation
_POLL_INTERVAL = 1  # seconds between enabled-file checks


def _read_cfg() -> dict:
    try:
        return json.loads(open(_ACTIVE_FILE).read())
    except ValueError, OSError:
        return {}


def _start():
    cfg = _read_cfg()
    nframes = int(cfg.get('nframes', _DEFAULT_NFRAMES))
    tracemalloc.start(nframes)
    logger.info(f'tracemalloc started with {nframes=}')


def _stop():
    tracemalloc.stop()
    logger.info('tracemalloc stopped')


def _dump():
    """Write a snapshot to a timestamped file."""
    snapshot = tracemalloc.take_snapshot()
    ts = datetime.datetime.now(tz=datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')
    dump_path = os.path.join(_DIR, f'dump_{ts}.txt')

    with open(dump_path, 'w') as f:
        for stat in snapshot.statistics('traceback')[:50]:
            f.write(f'{stat.size / 1024:.1f} KiB — {stat.count} object(s)\n')
            for frame in stat.traceback:
                f.write(f'  File "{frame.filename}", line {frame.lineno}, in {frame.name}\n')
            f.write('\n')

    logger.info(f'tracemalloc snapshot written to {dump_path}')


async def tracemalloc_watcher():
    """Background task: polls for changes in $TRACEMALLOC_DIR every 1s.

    Workflow:
        # start tracing (optional config)
        kubectl exec -n delivery <pod> -- sh -c \
            'mkdir -p $TRACEMALLOC_DIR && echo "{\"nframes\":15}" > $TRACEMALLOC_DIR/active'

        # request a snapshot (e.g. between load bursts)
        kubectl exec -n delivery <pod> -- touch $TRACEMALLOC_DIR/trigger

        # stop tracing, then copy all dumps to local ./dumps/
        kubectl exec -n delivery <pod> -- rm $TRACEMALLOC_DIR/active
        kubectl cp delivery/<pod>:$TRACEMALLOC_DIR ./dumps/

    Only runs when the TRACEMALLOC_DIR environment variable is set.
    Snapshots are written on demand when $TRACEMALLOC_DIR/trigger is present
    (trigger is removed after dump). The snapshot is taken in a thread-pool executor
    so the blocking tracemalloc.take_snapshot() does not stall the event loop. Note
    that take_snapshot() still acquires the GIL — avoid triggering during load tests.
    """
    if not _DIR:
        return
    loop = asyncio.get_running_loop()

    while True:
        await asyncio.sleep(_POLL_INTERVAL)
        try:
            is_active = os.path.exists(_ACTIVE_FILE)

            if not is_active and tracemalloc.is_tracing():
                _stop()
                continue

            if is_active and not tracemalloc.is_tracing():
                _start()
                continue

            if not (is_active and tracemalloc.is_tracing()):
                continue

            triggered = os.path.exists(_TRIGGER_FILE)
            if triggered:
                try:
                    os.remove(_TRIGGER_FILE)
                except OSError:
                    pass
                await loop.run_in_executor(None, _dump)

        except Exception:
            logger.exception('tracemalloc watcher error')
