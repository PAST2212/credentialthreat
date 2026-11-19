import asyncio
from collections import deque
from contextlib import ExitStack, contextmanager
import multiprocessing as mp
from multiprocessing.pool import Pool
import signal


class AsyncCancellationManager:
    def __init__(self):
        self._tasks: set[asyncio.Future] = set()
        self.cancelled = False

    def add_task(self, task: asyncio.Future) -> None:
        self._tasks.add(task)
        if self.cancelled:
            task.cancel()

    def remove_task(self, task: asyncio.Future) -> None:
        self._tasks.discard(task)

    async def gather(self, requests):
        batch = asyncio.gather(*requests, return_exceptions=True)
        self.add_task(batch)
        try:
            return await batch
        finally:
            self.remove_task(batch)

    async def run_window(self, items, handle, window: int) -> list:
        """Await handle(item) for every item with at most `window` running; results keep input order.

        A free slot takes the next item at once, so one slow item does not hold back the others.
        After cancel_all no further item starts. A failing item yields its exception as result.
        """
        items = list(items)
        results: list = [None] * len(items)
        pending = iter(enumerate(items))

        async def slot():
            for index, item in pending:
                if self.cancelled:
                    return
                try:
                    results[index] = await handle(item)
                except Exception as exc:
                    results[index] = exc

        await self.gather([slot() for _ in range(min(max(1, window), len(items)))])
        return results

    async def cancel_all(self) -> None:
        self.cancelled = True
        active = tuple(self._tasks)
        for task in active:
            task.cancel()
        if active:
            await asyncio.gather(*active, return_exceptions=True)
            self._tasks.difference_update(active)


class ScanInterrupted(SystemExit):
    """Unwind asyncio tasks even in stages that handle KeyboardInterrupt locally."""


class GracefulKiller:
    def __init__(self):
        self.pending_signal = None
        self._in_pool = False

    @contextmanager
    def handle_signals(self):
        with ExitStack() as restore:
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous = signal.signal(sig, self._exit_gracefully)
                restore.callback(signal.signal, sig, previous)
            yield self

    def _exit_gracefully(self, signum: int, frame) -> None:
        if self.pending_signal is None:
            self.pending_signal = signal.Signals(signum)
            if not self._in_pool:
                raise ScanInterrupted(self.pending_signal.name)

    @contextmanager
    def defer_pool_signals(self):
        """Keep pool creation and teardown intact when a signal arrives."""
        self._in_pool = True
        try:
            yield
        finally:
            self._in_pool = False
        self.check_interrupt()

    def check_interrupt(self):
        if self.pending_signal is not None:
            raise ScanInterrupted(self.pending_signal.name)

    def pool_results(self, pool, worker, chunks):
        pending = deque()
        for chunk in chunks:
            self.check_interrupt()
            pending.append(pool.apply_async(worker, (chunk,)))
        while pending:
            result = pending.popleft()
            while not result.ready():
                self.check_interrupt()
                result.wait(0.1)
            self.check_interrupt()
            yield result.get()


def init_worker():
    """Route interrupts through the parent and let the pool terminate workers."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


def create_pool(processes: int) -> Pool:
    """The pool context terminates unfinished jobs on exit."""
    return mp.Pool(processes=processes, initializer=init_worker)
