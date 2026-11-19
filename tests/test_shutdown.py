import asyncio
import contextlib
import io
import multiprocessing as mp
import os
from pathlib import Path
import runpy
import signal
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import Mock, patch

from credentialthreat.core.interrupt_handler import create_pool, init_worker


ROOT = Path(__file__).resolve().parents[1]


def hold_job(directory):
    directory = Path(directory)
    (directory / "started").touch()
    time.sleep(1.2)
    (directory / "finished").touch()


HOLD_DIRECTORY = "CREDENTIALTHREAT_TEST_HOLD_DIRECTORY"


def hold_first_chunk(args):
    # Spawned workers inherit the environment, so the directory travels outside the scan arguments.
    hold_job(os.environ[HOLD_DIRECTORY])
    return [], set()


def wait_until_started(directory):
    deadline = time.monotonic() + 10
    while not (directory / "started").exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("Synthetic worker did not start")
        time.sleep(0.01)


def wait_for_termination(ready):
    init_worker()
    ready.set()
    signal.pause()


def signal_while_blocked(started, signum, sent):
    if started.wait(3):
        time.sleep(0.05)
        sent.append(time.monotonic())
        if os.name == "nt":
            signal.raise_signal(signum)
        else:
            os.kill(os.getpid(), signum)


class ShutdownTests(unittest.TestCase):
    def test_signal_during_discovery_stops_before_internal_link_scan(self):
        main = runpy.run_path(str(ROOT / "credentialthreat.py"))["main"]
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum.name), contextlib.ExitStack() as stack:
                events = []

                async def discovery(domains):
                    events.append("discovery started")
                    try:
                        signal.raise_signal(signum)
                        await asyncio.sleep(0)
                        events.append("discovery continued")
                    finally:
                        events.append("discovery cleaned up")
                    return []

                for sig in (signal.SIGINT, signal.SIGTERM):
                    stack.callback(signal.signal, sig, signal.getsignal(sig))
                files = Mock()
                files.return_value.get_domains.return_value = ["example.invalid"]
                pool = Mock(side_effect=AssertionError("Internal link scan started after signal"))
                utils = Mock()
                utils.get_workers.return_value = 1
                stack.enter_context(patch.dict(main.__globals__, {
                    "time": Mock(), "utils": utils, "ManageFiles": files,
                    "parse_arguments": Mock(), "create_pool": pool,
                }))
                stack.enter_context(patch("credentialthreat.core.subdomainsearch.async_subdomain_report",
                                          new=discovery))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                self.assertNotEqual(main(), 0)
                self.assertEqual(events, ["discovery started", "discovery cleaned up"])
                pool.assert_not_called()
                files.write_csv_result_file.assert_not_called()

    def test_signal_wakes_idle_discovery_event_loop(self):
        main = runpy.run_path(str(ROOT / "credentialthreat.py"))["main"]
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum.name), contextlib.ExitStack() as stack:
                started = threading.Event()
                sent = []

                async def idle_discovery(self, domains):
                    started.set()
                    await asyncio.sleep(2.5)

                for sig in (signal.SIGINT, signal.SIGTERM):
                    stack.callback(signal.signal, sig, signal.getsignal(sig))
                stack.callback(asyncio.set_event_loop_policy, asyncio.get_event_loop_policy())
                stack.enter_context(patch.object(mp, "set_start_method"))
                files = Mock()
                files.return_value.get_domains.return_value = ["example.invalid"]
                pool = Mock(side_effect=AssertionError("Pool opened after signal"))
                stack.enter_context(patch.dict(main.__globals__, {
                    "time": Mock(), "ManageFiles": files, "parse_arguments": Mock(),
                    "create_pool": pool,
                }))
                stack.enter_context(patch("credentialthreat.core.subdomainsearch.SubdomainScanner.get_report",
                                          new=idle_discovery))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                sender = threading.Thread(target=signal_while_blocked, args=(started, signum, sent))
                sender.start()
                try:
                    self.assertNotEqual(main(), 0)
                finally:
                    sender.join(4)
                self.assertTrue(sent, "Signal was never sent")
                self.assertLess(time.monotonic() - sent[0], 1.0, "Loop waited for its 2.5s timer")
                pool.assert_not_called()

    def test_sigterm_interrupts_startup_delay(self):
        main = runpy.run_path(str(ROOT / "credentialthreat.py"))["main"]
        started = threading.Event()
        sent = []

        def sleep(seconds):
            started.set()
            time.sleep(seconds)

        with contextlib.ExitStack() as stack:
            for sig in (signal.SIGINT, signal.SIGTERM):
                stack.callback(signal.signal, sig, signal.getsignal(sig))
            files = Mock()
            files.return_value.get_domains.return_value = ["example.invalid"]
            utils = Mock()
            utils.get_workers.side_effect = AssertionError("Startup continued")
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(sleep=sleep), "ManageFiles": files,
                "utils": utils, "parse_arguments": Mock(),
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            sender = threading.Thread(target=signal_while_blocked, args=(started, signal.SIGTERM, sent))
            sender.start()
            try:
                self.assertNotEqual(main(), 0)
            finally:
                sender.join(4)
            self.assertTrue(sent)
            self.assertLess(time.monotonic() - sent[0], 1.0, "Startup slept through SIGTERM")
            utils.get_workers.assert_not_called()

    def test_worker_restores_default_termination_handler(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            self.addCleanup(signal.signal, signum, signal.getsignal(signum))
        signal.signal(signal.SIGTERM, lambda *_: None)
        init_worker()
        self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
        self.assertEqual(signal.getsignal(signal.SIGINT), signal.SIG_IGN)

    @unittest.skipUnless(os.name == "posix", "requires POSIX fork and SIGTERM")
    def test_forked_worker_exits_on_sigterm(self):
        context = mp.get_context("fork")
        ready = context.Event()
        parent_handler = signal.signal(signal.SIGTERM, lambda *_: None)
        self.addCleanup(signal.signal, signal.SIGTERM, parent_handler)
        child = context.Process(target=wait_for_termination, args=(ready,))
        child.start()
        try:
            self.assertTrue(ready.wait(5))
            child.terminate()
            child.join(2)
            self.assertEqual(child.exitcode, -signal.SIGTERM)
        finally:
            if child.is_alive():
                child.kill()
            child.join()
            child.close()

    def test_cli_interrupts_a_running_chunk_before_its_first_result(self):
        main = runpy.run_path(str(ROOT / "credentialthreat.py"))["main"]
        with TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            directory = Path(tmp)
            for signum in (signal.SIGINT, signal.SIGTERM):
                stack.callback(signal.signal, signum, signal.getsignal(signum))
            stack.enter_context(patch.dict(os.environ, {HOLD_DIRECTORY: tmp}))
            files = Mock()
            files.return_value.get_domains.return_value = ["example.invalid"]
            utils = Mock()
            utils.get_workers.return_value = 1
            utils.plan_chunks.side_effect = lambda items, workers: [list(items)]
            utils.host_connections_per_worker.return_value = 2
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(), "utils": utils, "ManageFiles": files,
                "parse_arguments": lambda: type("Args", (), {"command": None, "limit": 1})(),
                "scan_subdomain_report": lambda domains: [],
                "process_chunks_for_internallinks": hold_first_chunk,
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

            def interrupt_when_busy():
                wait_until_started(directory)
                signal.raise_signal(signal.SIGINT)

            sender = threading.Thread(target=interrupt_when_busy)
            sender.start()
            try:
                self.assertNotEqual(main(), 0)
            finally:
                sender.join(12)
            self.assertTrue((directory / "started").exists())
            self.assertFalse((directory / "finished").exists(), "CLI waited for the first result")
            files.write_csv_result_file.assert_not_called()

    def test_leaving_pool_early_does_not_run_queued_job(self):
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            queued = directory / "queued"
            with create_pool(1) as pool:
                pool.apply_async(hold_job, (tmp,))
                pool.apply_async(queued.touch)
                wait_until_started(directory)
            self.assertFalse(queued.exists(), "Pool drained jobs after exit")
