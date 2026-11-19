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
from http_doubles import response as http_response


ROOT = Path(__file__).resolve().parents[1]
CLI = runpy.run_path(str(ROOT / "credentialthreat.py"))


class CliTests(unittest.TestCase):
    def test_empty_stage_finishes_report_without_workers(self):
        main = CLI["main"]
        host = "shop.example.com"
        for no_pages in (True, False):
            for discovery_failed in (True, False):
                with self.subTest(no_pages=no_pages, discovery_failed=discovery_failed), contextlib.ExitStack() as stack:
                    files_mock = Mock()
                    files_mock.return_value.get_domains.return_value = [host]
                    pools = Mock(wraps=ThreadPool)
                    links = Mock(return_value=([] if no_pages else [f"https://{host}/"], set()))
                    resources = Mock(return_value=([], set(), {}))
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
                    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                    with self.assertLogs(level="INFO") as logs:
                        self.assertEqual(main(), int(discovery_failed))
                    self.assertEqual(pools.call_count, 1 if no_pages else 2)
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
        response.__aenter__.return_value = http_response(200, body)

        def links(args):
            seen_hosts.extend(args[0])
            return [internal_page, internal_page, sibling], set()

        def resources(args):
            seen_pages.extend(args[0])
            return [utils.ScrapNetworkUrls(base, resource), utils.ScrapNetworkUrls(base, sibling)], set(), {}

        def matches(arg):
            seen_resources.extend(arg[0])
            return credential_worker(arg)

        stdout = io.StringIO()
        with TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(files, "OUTPUT_DIRECORY", Path(tmp)))
            stack.enter_context(patch.object(files.ManageFiles, "get_domains", return_value=[host]))
            stack.enter_context(patch.object(utils, "get_workers", return_value=1))
            stack.enter_context(patch.object(utils, "configure_platform_settings"))
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

    def test_each_host_and_page_enters_its_stage_once(self):
        main = CLI["main"]
        root = "example.com"
        seen_hosts, seen_pages = [], []
        links = [
            "https://shop.example.com", "https://shop.example.com/", "https://shop.example.com/#top",
            "https://shop.example.com/p?a=1#x", "https://shop.example.com/p?a=1",
            "https://shop.example.com/doc.pdf", "tel:+49123", "shop.example.com",
        ]

        def link_worker(args):
            seen_hosts.extend(args[0])
            return links, set()

        def page_worker(args):
            seen_pages.extend(args[0])
            return [], set(), {}

        with contextlib.ExitStack() as stack:
            files_mock = Mock()
            files_mock.return_value.get_domains.return_value = [root]
            stack.enter_context(patch.object(CLI["utils"], "get_workers", return_value=2))
            stack.enter_context(patch.object(CLI["utils"], "configure_platform_settings"))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=10),
                "ManageFiles": files_mock, "create_pool": ThreadPool,
                "scan_subdomain_report": lambda domains: [
                    QueryResult("RapidDNS", root, 3, frozenset(["Shop.example.com", "shop.example.com", root]))
                ],
                "process_chunks_for_internallinks": link_worker, "process_chunks_for_networksearch": page_worker,
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertLogs(level="INFO"):
                self.assertEqual(main(), 0)
        self.assertCountEqual(seen_hosts, [root, "shop.example.com"])
        self.assertCountEqual(seen_pages, ["https://shop.example.com/", "https://shop.example.com/p?a=1"])

    def test_page_and_resource_stages_use_every_worker_without_sampling_requests(self):
        main = CLI["main"]
        utils = CLI["utils"]
        host = "shop.example.com"
        pages = [f"https://{host}/p/{i}" for i in range(9)]
        page_chunks, resource_chunks = [], []

        def page_worker(args):
            page_chunks.append(list(args[0]))
            return [utils.ScrapNetworkUrls(page, page + ".js") for page in args[0]], set(), {}

        def resource_worker(arg):
            resource_chunks.append(list(arg[0]))
            return [], {}

        with contextlib.ExitStack() as stack:
            files_mock = Mock()
            files_mock.return_value.get_domains.return_value = [host]
            requests = stack.enter_context(patch("aiohttp.ClientSession._request", new=Mock(side_effect=OSError("offline"))))
            stack.enter_context(patch.object(utils, "get_workers", return_value=3))
            stack.enter_context(patch.object(utils, "configure_platform_settings"))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=100),
                "ManageFiles": files_mock, "create_pool": ThreadPool,
                "scan_subdomain_report": lambda domains: [QueryResult("crt.sh", host, 0)],
                "process_chunks_for_internallinks": lambda args: (pages, set()),
                "process_chunks_for_networksearch": page_worker,
                "process_chunks_for_credentialsearch": resource_worker,
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertLogs(level="INFO"):
                self.assertEqual(main(), 0)
        requests.assert_not_called()
        self.assertGreaterEqual(len(page_chunks), 3)
        self.assertGreaterEqual(len(resource_chunks), 3)
        self.assertCountEqual([url for chunk in page_chunks for url in chunk], pages)

    def test_workers_share_one_connection_budget_per_host(self):
        main = CLI["main"]
        utils = CLI["utils"]
        host = "shop.example.com"
        page = f"https://{host}/"
        budgets = []

        def remember(result):
            def worker(args):
                budgets.append(args[-1])
                return result
            return worker

        with contextlib.ExitStack() as stack:
            files_mock = Mock()
            files_mock.return_value.get_domains.return_value = [host]
            stack.enter_context(patch.object(utils, "get_workers", return_value=5))
            stack.enter_context(patch.object(utils, "configure_platform_settings"))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=100),
                "ManageFiles": files_mock, "create_pool": ThreadPool,
                "scan_subdomain_report": lambda domains: [QueryResult("crt.sh", host, 0)],
                "process_chunks_for_internallinks": remember(([page], {})),
                "process_chunks_for_networksearch": remember(([utils.ScrapNetworkUrls(page, page)], set(), {})),
                "process_chunks_for_credentialsearch": remember(([], {})),
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertLogs(level="INFO"):
                self.assertEqual(main(), 0)
        self.assertEqual(budgets, [5, 5, 5])

    def test_each_stage_reports_why_urls_were_skipped(self):
        main = CLI["main"]
        utils = CLI["utils"]
        host = "shop.example.com"
        page = f"https://{host}/"

        with contextlib.ExitStack() as stack:
            files_mock = Mock()
            files_mock.return_value.get_domains.return_value = [host]
            stack.enter_context(patch.object(utils, "get_workers", return_value=1))
            stack.enter_context(patch.object(utils, "configure_platform_settings"))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=100),
                "ManageFiles": files_mock, "create_pool": ThreadPool,
                "scan_subdomain_report": lambda domains: [QueryResult("crt.sh", host, 0)],
                "process_chunks_for_internallinks": lambda args: (
                    [page], {"ok": 1, "redirect skipped": 2, "connect timeout": 3}),
                "process_chunks_for_networksearch": lambda args: (
                    [utils.ScrapNetworkUrls(page, page)], set(), {"ok": 1}),
                "process_chunks_for_credentialsearch": lambda args: ([], {"ok": 4, "HTTP 429": 5}),
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertLogs(level="INFO") as logs:
                self.assertEqual(main(), 0)
        lines = {record.getMessage(): record.levelname for record in logs.records if "requests:" in record.getMessage()}
        self.assertEqual(lines, {
            "Internal URL scan requests: ok=1, skipped=5 (connect timeout=3, redirect skipped=2)": "WARNING",
            "Network resource scan requests: ok=1, skipped=0": "INFO",
            "Credential scan requests: ok=4, skipped=5 (HTTP 429=5)": "WARNING",
        })

    def test_worker_failure_reaches_the_caller(self):
        worker = CLI["process_chunks_for_networksearch"]
        with patch.object(CLI["ScanerNetworkResources"], "get_results",
                          new=AsyncMock(side_effect=RuntimeError("synthetic failure"))):
            with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
                worker(([], [], None, 2))

    def test_worker_exit_is_reported_as_an_error(self):
        worker = CLI["process_chunks_for_networksearch"]
        with patch.object(CLI["ScanerNetworkResources"], "get_results",
                          new=AsyncMock(side_effect=SystemExit(2))):
            with self.assertRaises(RuntimeError):
                worker(([], [], None, 2))

    def test_failed_chunk_makes_cli_exit_before_final_report(self):
        main = CLI["main"]
        files_mock = Mock()
        files_mock.return_value.get_domains.return_value = ["example.invalid"]
        utils = Mock()
        utils.get_workers.return_value = 1
        utils.plan_chunks.side_effect = lambda items, workers: [list(items)]
        utils.host_connections_per_worker.return_value = 2
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
                "process_chunks_for_internallinks": lambda _: (["https://example.invalid/"], set()),
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
