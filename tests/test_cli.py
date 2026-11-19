import contextlib
import csv
import io
from multiprocessing.pool import ThreadPool
from pathlib import Path
import runpy
import signal
import subprocess
import time
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from tldextract.cache import DiskCache

from credentialthreat.core import files
from credentialthreat.core.discovery import QueryResult


ROOT = Path(__file__).resolve().parents[1]
CLI = runpy.run_path(str(ROOT / "credentialthreat.py"))


class CliTests(unittest.TestCase):
    def test_empty_calibration_returns_configured_minimum_without_sampling(self):
        utils = CLI["utils"]
        with patch.object(utils, "ScanerCredentials", wraps=utils.ScanerCredentials) as sampler, self.assertNoLogs(level="ERROR"):
            self.assertEqual(utils.calculate_optimal_chunk_size([], min_size=7), 7)
        sampler.assert_not_called()

    def test_empty_stage_finishes_report_without_calibration_or_workers(self):
        main = CLI["main"]
        host = "shop.example.com"
        for no_pages in (True, False):
            for discovery_failed in (True, False):
                with self.subTest(no_pages=no_pages, discovery_failed=discovery_failed), contextlib.ExitStack() as stack:
                    files_mock = Mock()
                    files_mock.return_value.get_domains.return_value = [host]
                    pools = Mock(wraps=ThreadPool)
                    links = Mock(return_value=([], {host} if no_pages else set()))
                    resources = Mock(return_value=([], set()))
                    matches = Mock(return_value=[])
                    discovery = QueryResult("crt.sh", host, None, reason="timeout") if discovery_failed else QueryResult("crt.sh", host, 0)
                    stack.enter_context(patch.dict(main.__globals__, {
                        "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=10),
                        "ManageFiles": files_mock, "create_pool": pools, "scan_subdomain_report": lambda domains: [discovery],
                        "process_chunks_for_internallinks": links, "process_chunks_for_networksearch": resources,
                        "process_chunks_for_credentialsearch": matches,
                    }))
                    stack.enter_context(patch.object(CLI["utils"], "get_workers", return_value=1))
                    stack.enter_context(patch.object(CLI["utils"], "configure_platform_settings"))
                    sizing = stack.enter_context(patch.object(CLI["utils"], "calculate_optimal_chunk_size", return_value=8))
                    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                    with self.assertLogs(level="INFO") as logs:
                        self.assertEqual(main(), int(discovery_failed))
                    self.assertEqual(pools.call_count, 1 if no_pages else 2)
                    self.assertEqual(sizing.call_count, int(not no_pages))
                    self.assertEqual(resources.call_count, int(not no_pages))
                    matches.assert_not_called()
                    files_mock.write_csv_result_file.assert_called_once_with(iterables=[])
                    output = "\n".join(logs.output)
                    self.assertIn("Unverified credential matches: 0", output)
                    self.assertEqual("incomplete discovery" in output, discovery_failed)

    def test_startup_uses_bundled_suffixes_with_an_empty_cache(self):
        main = CLI["main"]
        files_mock = Mock()
        files_mock.return_value.get_domains.return_value = ["docs.example.com"]
        discovery = Mock(side_effect=RuntimeError("end of startup fixture"))
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("tldextract.tldextract.DiskCache", return_value=DiskCache(None)))
            http = stack.enter_context(patch("requests.Session.send", side_effect=AssertionError("remote lookup")))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(), "utils": Mock(), "ManageFiles": files_mock,
                "parse_arguments": Mock(), "scan_subdomain_report": discovery,
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertLogs(level="ERROR"):
                self.assertEqual(main(), 1)
        http.assert_not_called()
        discovery.assert_called_once_with(domains=["docs.example.com"])

    def test_configured_scope_and_redaction_survive_the_full_reporting_path(self):
        main = CLI["main"]
        host = "docs.example.com"
        base = "https://" + host
        internal_page = base + "/guide"
        marker = "PRIVATEFIXTUREONLY"
        resource = base + "/app.js?session=" + marker
        sibling = "https://sibling.example.com/"
        seen_hosts, seen_pages, seen_resources = [], [], []
        utils = CLI["utils"]
        credential_worker = CLI["process_chunks_for_credentialsearch"]
        synthetic_id = "AKIA" + "TEST" * 4
        body = f'api_key = "{synthetic_id}"; public_key = "{marker}";'
        response = MagicMock()
        response.__aenter__.return_value = Mock(status=200, text=AsyncMock(return_value=body))

        def links(args):
            seen_hosts.extend(args[0])
            return [internal_page, internal_page, sibling], set()

        def resources(args):
            seen_pages.extend(args[0])
            return [utils.ScrapNetworkUrls(base, resource), utils.ScrapNetworkUrls(base, sibling)], set()

        def matches(pairs):
            seen_resources.extend(pairs)
            return credential_worker(pairs)

        stdout = io.StringIO()
        with TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(files, "OUTPUT_DIRECORY", Path(tmp)))
            stack.enter_context(patch.object(files.ManageFiles, "get_domains", return_value=[host]))
            stack.enter_context(patch.object(utils, "get_workers", return_value=1))
            stack.enter_context(patch.object(utils, "configure_platform_settings"))
            stack.enter_context(patch.object(utils, "calculate_optimal_chunk_size", return_value=10))
            stack.enter_context(patch("aiohttp.ClientSession.get", return_value=response))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=10),
                "create_pool": ThreadPool,
                "scan_subdomain_report": lambda domains: [
                    QueryResult("crt.sh", host, 2, frozenset(["child." + host, "sibling.example.com"]))
                ],
                "process_chunks_for_internallinks": links, "process_chunks_for_networksearch": resources,
                "process_chunks_for_credentialsearch": matches,
            }))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            with self.assertLogs(level="INFO") as logs:
                self.assertEqual(main(), 0)
            report, = Path(tmp).glob("*.csv")
            with report.open(encoding="utf-8", newline="") as stream:
                header, *rows = csv.reader(stream, delimiter=";")
        self.assertEqual(set(seen_hosts), {host, "child." + host})
        self.assertEqual(seen_pages.count(internal_page), 1)
        self.assertNotIn(sibling, seen_pages)
        self.assertEqual(seen_resources, [(base, resource)])
        self.assertEqual(len(header), 4)
        self.assertEqual([len(row) for row in rows], [4, 4])
        self.assertIn("api_key + aws_keys", rows[0][3])
        console = stdout.getvalue() + " ".join(logs.output)
        self.assertNotIn(host, console)
        self.assertIn("Unverified credential matches: 2 (affected resources: 1)", console)
        self.assertNotIn(marker, console + str(rows))
        self.assertNotIn(synthetic_id, console + str(rows))

    def test_worker_failure_reaches_the_caller(self):
        worker = CLI["process_chunks_for_networksearch"]
        with patch.object(CLI["ScanerNetworkResources"], "get_results",
                          new=AsyncMock(side_effect=RuntimeError("synthetic failure"))):
            with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
                worker(([], [], None))

    def test_worker_exit_is_reported_as_an_error(self):
        worker = CLI["process_chunks_for_networksearch"]
        with patch.object(CLI["ScanerNetworkResources"], "get_results",
                          new=AsyncMock(side_effect=SystemExit(2))):
            with self.assertRaises(RuntimeError):
                worker(([], [], None))

    def test_failed_chunk_makes_cli_exit_before_final_report(self):
        main = CLI["main"]
        files_mock = Mock()
        files_mock.return_value.get_domains.return_value = ["example.invalid"]
        utils = Mock()
        utils.get_workers.return_value = utils.calculate_optimal_chunk_size.return_value = 1
        utils.remove_byte_content_urls.side_effect = list
        priorities = Mock()
        priorities.return_value.prioritize_urls.side_effect = lambda urls, limit: urls
        with contextlib.ExitStack() as stack:
            for signum in (signal.SIGINT, signal.SIGTERM):
                stack.callback(signal.signal, signum, signal.getsignal(signum))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(patch.dict(main.__globals__, {
                "parse_arguments": Mock(), "time": Mock(), "utils": utils,
                "ManageFiles": files_mock, "create_pool": ThreadPool,
                "scan_subdomain_report": lambda domains: [],
                "process_chunks_for_internallinks": lambda _: ([], set()),
                "UrlPrioritizer": priorities,
            }))
            marker = "PRIVATEQUERYFIXTURE"
            stack.enter_context(patch.object(CLI["ScanerNetworkResources"], "get_results",
                                             new=AsyncMock(side_effect=RuntimeError("failed chunk: " + marker))))
            with self.assertLogs(level="ERROR") as messages:
                self.assertEqual(main(), 1)
            diagnostic = " ".join(messages.output)
            self.assertNotIn(marker, diagnostic)
            self.assertIn("network scanning", diagnostic)
            self.assertIn("RuntimeError", diagnostic)
            files_mock.write_csv_result_file.assert_not_called()

    def test_unconfigured_checkout_exits_before_any_network_or_report(self):
        main = CLI["main"]
        with TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            for signum in (signal.SIGINT, signal.SIGTERM):
                stack.callback(signal.signal, signum, signal.getsignal(signum))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(patch.object(files, "INPUT_DIRECORY", Path(tmp)))
            report = stack.enter_context(patch.object(files.ManageFiles, "create_csv_result_file"))
            extractor = Mock(side_effect=AssertionError("Unexpected suffix-list lookup"))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(), "utils": Mock(), "parse_arguments": Mock(),
                "SUFFIXES": extractor,
            }))
            with self.assertLogs(level="WARNING") as messages:
                self.assertNotEqual(main(), 0)
            self.assertIn("domains.txt", " ".join(messages.output))
            extractor.assert_not_called()
            report.assert_not_called()

    def test_live_target_file_is_private_and_shipped_template_is_inert(self):
        target = "credentialthreat/data/input/domains.txt"
        tracked = subprocess.check_output(["git", "ls-files", "--", target], cwd=ROOT)
        self.assertEqual(tracked, b"", "The editable target file is tracked")
        self.assertEqual(subprocess.run(["git", "check-ignore", "-q", target], cwd=ROOT).returncode, 0)
        template = ROOT / "credentialthreat/data/input/domains.example.txt"
        self.assertTrue(template.is_file())
        self.assertFalse(any(row.strip() and not row.startswith("#")
                             for row in template.read_text().splitlines()))

    def test_contributor_guide_states_python_version_before_setup(self):
        guide = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("Python 3.12", guide.partition("python -m venv")[0])
