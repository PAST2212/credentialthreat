from collections import Counter
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
                    links = Mock(return_value=([] if no_pages else [f"https://{host}/"], [], set(), [], {}))
                    resources = Mock(return_value=([], set(), [], {}))
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
            return [internal_page, internal_page, sibling], [], set(), [], {}

        def resources(args):
            seen_pages.extend(args[0])
            return [utils.ScrapNetworkUrls(base, resource), utils.ScrapNetworkUrls(base, sibling)], set(), [], {}

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

    def test_page_is_fetched_once_and_its_candidates_reach_the_report(self):
        main = CLI["main"]
        host = "docs.example.com"
        base = "https://" + host
        page = base + "/guide"
        script = base + "/app.js"
        marker = "PRIVATEFIXTUREONLY"
        bodies = {
            page: f'<link rel="canonical" href="{page}"><script src="/app.js"></script>'
                  f'<script>var api_key = "{marker}";</script>',
            script: f'client_secret = "{marker}";',
        }
        requested = []

        def get(url, **kwargs):
            requested.append(url)
            manager = MagicMock()
            manager.__aenter__.return_value = http_response(200, bodies[url], {"Content-Type": "text/html"})
            return manager

        stdout = io.StringIO()
        with TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(files, "OUTPUT_DIRECORY", Path(tmp)))
            stack.enter_context(patch.object(files.ManageFiles, "get_domains", return_value=[host]))
            stack.enter_context(patch.object(CLI["utils"], "get_workers", return_value=1))
            stack.enter_context(patch.object(CLI["utils"], "configure_platform_settings"))
            stack.enter_context(patch("aiohttp.ClientSession.get", new=Mock(side_effect=get)))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=10),
                "create_pool": ThreadPool,
                "scan_subdomain_report": lambda domains: [QueryResult("crt.sh", host, 0)],
                "process_chunks_for_internallinks": lambda args: ([page], [], set(), [], {}),
            }))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            with self.assertLogs(level="INFO") as logs:
                self.assertEqual(main(), 0)
            report, = Path(tmp).glob("*.csv")
            with report.open(encoding="utf-8", newline="") as stream:
                header, *rows = csv.reader(stream, delimiter=";")
        self.assertCountEqual(requested, [page, script])
        self.assertCountEqual([row[3] for row in rows],
                              ["Unverified api_key [REDACTED]", "Unverified client_secret [REDACTED]"])
        self.assertEqual({(row[0], row[1]) for row in rows}, {(base, base)})
        console = stdout.getvalue() + " ".join(logs.output)
        self.assertIn("Unverified credential matches: 2 (affected resources: 2)", console)
        self.assertNotIn(marker, console + str(rows))

    def test_page_candidates_are_reported_when_no_resources_remain(self):
        main = CLI["main"]
        host = "shop.example.com"
        page = f"https://{host}/"
        candidate = ("https://" + host, "https://" + host, [("api_key", "[REDACTED]")])
        files_mock = Mock()
        files_mock.return_value.get_domains.return_value = [host]
        pools = Mock(wraps=ThreadPool)
        matches = Mock(return_value=([], {}, []))
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(CLI["utils"], "get_workers", return_value=1))
            stack.enter_context(patch.object(CLI["utils"], "configure_platform_settings"))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=10),
                "ManageFiles": files_mock, "create_pool": pools,
                "scan_subdomain_report": lambda domains: [QueryResult("crt.sh", host, 0)],
                "process_chunks_for_internallinks": lambda args: ([page], [], set(), [], {}),
                "process_chunks_for_networksearch": lambda args: ([], {page}, [candidate], {"ok": 1}),
                "process_chunks_for_credentialsearch": matches,
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertLogs(level="INFO") as logs:
                self.assertEqual(main(), 0)
        matches.assert_not_called()
        self.assertEqual(pools.call_count, 2)
        files_mock.write_csv_result_file.assert_called_once_with(iterables=[candidate])
        self.assertIn("Unverified credential matches: 1 (affected resources: 1)", " ".join(logs.output))

    def test_start_page_candidates_are_reported_when_no_other_page_or_resource_remains(self):
        main = CLI["main"]
        host = "shop.example.com"
        page = f"https://{host}/"
        candidate = ("https://" + host, "https://" + host, [("api_key", "[REDACTED]")])
        files_mock = Mock()
        files_mock.return_value.get_domains.return_value = [host]
        pools = Mock(wraps=ThreadPool)
        page_worker = Mock(return_value=([], set(), [], {}))
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(CLI["utils"], "get_workers", return_value=1))
            stack.enter_context(patch.object(CLI["utils"], "configure_platform_settings"))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=10),
                "ManageFiles": files_mock, "create_pool": pools,
                "scan_subdomain_report": lambda domains: [QueryResult("crt.sh", host, 0)],
                "process_chunks_for_internallinks": lambda args: ([page], [], {page}, [candidate], {"ok": 1}),
                "process_chunks_for_networksearch": page_worker,
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertLogs(level="INFO"):
                self.assertEqual(main(), 0)
        page_worker.assert_not_called()
        self.assertEqual(pools.call_count, 1)
        files_mock.write_csv_result_file.assert_called_once_with(iterables=[candidate])

    def test_resource_limit_counts_only_resources_that_are_not_pages(self):
        main = CLI["main"]
        utils = CLI["utils"]
        host = "shop.example.com"
        pages = [f"https://{host}/p/{index}" for index in range(2)]
        scripts = [f"https://{host}/s/{index}.txt" for index in range(2)]
        seen_resources = []

        def page_worker(args):
            # Every page links both pages (e.g. canonical and alternate links) and one script.
            found = [utils.ScrapNetworkUrls(page, other) for page in args[0] for other in pages]
            found += [utils.ScrapNetworkUrls(page, script) for page, script in zip(pages, scripts)]
            return found, set(args[0]), [], {"ok": len(args[0])}

        def resource_worker(arg):
            seen_resources.extend(arg[0])
            return [], {}, []

        with contextlib.ExitStack() as stack:
            files_mock = Mock()
            files_mock.return_value.get_domains.return_value = [host]
            stack.enter_context(patch.object(utils, "get_workers", return_value=1))
            stack.enter_context(patch.object(utils, "configure_platform_settings"))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=2),
                "ManageFiles": files_mock, "create_pool": ThreadPool,
                "scan_subdomain_report": lambda domains: [QueryResult("crt.sh", host, 0)],
                "process_chunks_for_internallinks": lambda args: (pages, [], set(), [], {}),
                "process_chunks_for_networksearch": page_worker,
                "process_chunks_for_credentialsearch": resource_worker,
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertLogs(level="INFO"):
                self.assertEqual(main(), 0)
        self.assertCountEqual([resource for _, resource in seen_resources], scripts)

    def test_url_limits_rank_urls_without_the_configured_domain(self):
        # The configured domain contains the pattern `acl`. Ranked with it, every URL is high priority and a URL
        # limit keeps the alphabetically first ones.
        main = CLI["main"]
        utils = CLI["utils"]
        host = "miracle.example"
        page = f"https://www.{host}/"
        links = [f"https://www.{host}/a/about", f"https://www.{host}/z/admin/"]
        resources = [f"https://www.{host}/a/app.css", f"https://www.{host}/z/secret-settings.css"]
        seen_pages, seen_resources = [], []

        def page_worker(args):
            seen_pages.extend(args[0])
            return [utils.ScrapNetworkUrls(page, resource) for resource in resources], set(args[0]), [], {"ok": 1}

        def resource_worker(arg):
            seen_resources.extend(resource for _, resource in arg[0])
            return [], {}, []

        with contextlib.ExitStack() as stack:
            files_mock = Mock()
            files_mock.return_value.get_domains.return_value = [host]
            stack.enter_context(patch.object(utils, "get_workers", return_value=1))
            stack.enter_context(patch.object(utils, "configure_platform_settings"))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=1),
                "ManageFiles": files_mock, "create_pool": ThreadPool,
                "scan_subdomain_report": lambda domains: [QueryResult("crt.sh", host, 0)],
                "process_chunks_for_internallinks": lambda args: (links, [], set(), [], {}),
                "process_chunks_for_networksearch": page_worker,
                "process_chunks_for_credentialsearch": resource_worker,
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertLogs(level="INFO"):
                self.assertEqual(main(), 0)
        self.assertEqual(seen_pages, [links[1]])
        self.assertEqual(seen_resources, [resources[1]])
        modules = [(page, f"https://www.{host}/a/module.js"), (page, f"https://www.{host}/z/auth-module.js")]
        with patch("logging.info"):
            kept, skipped = CLI["_next_imports"](modules, set(), [host], 1)
        self.assertEqual((kept, skipped), ([modules[1]], 1))

    def run_with_imports(self, imports, limit):
        """Scan one page with one script; the resource worker reports `imports[resource]` for each resource."""
        main = CLI["main"]
        utils = CLI["utils"]
        host = "shop.example.com"
        page = f"https://{host}/"
        rounds = []
        pools = Mock(wraps=ThreadPool)

        def resource_worker(arg):
            rounds.append(sorted(resource for _, resource in arg[0]))
            return [], {"ok": len(arg[0])}, [found for _, resource in arg[0] for found in imports.get(resource, [])]

        with contextlib.ExitStack() as stack:
            files_mock = Mock()
            files_mock.return_value.get_domains.return_value = [host]
            stack.enter_context(patch.object(utils, "get_workers", return_value=1))
            stack.enter_context(patch.object(utils, "configure_platform_settings"))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=limit),
                "ManageFiles": files_mock, "create_pool": pools,
                "scan_subdomain_report": lambda domains: [QueryResult("crt.sh", host, 0)],
                "process_chunks_for_internallinks": lambda args: ([page], [], set(), [], {}),
                "process_chunks_for_networksearch": lambda args: (
                    [utils.ScrapNetworkUrls(page, page + "app.js")], {page}, [], {"ok": 1}),
                "process_chunks_for_credentialsearch": resource_worker,
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertLogs(level="INFO") as logs:
                self.assertEqual(main(), 0)
        return rounds, pools.call_count, "\n".join(logs.output)

    def test_imported_modules_are_scanned_in_later_rounds_of_the_same_pool(self):
        page = "https://shop.example.com/"
        imports = {
            # Out of scope, already requested (the page, the script itself) and repeated imports are dropped.
            page + "app.js": [(page, page + "m/mod.js"), (page, "https://other.example.net/x.js"),
                              (page, page + "app.js"), (page, page), (page, page + "m/mod.js")],
            page + "m/mod.js": [(page, page + "m/lazy.js"), (page, page + "app.js")],
        }
        rounds, pools, output = self.run_with_imports(imports, limit=100)
        self.assertEqual(rounds, [[page + "app.js"], [page + "m/mod.js"], [page + "m/lazy.js"]])
        self.assertEqual(pools, 3)
        self.assertIn("Credential scan requests: ok=3, skipped=0", output)

    def test_imported_modules_count_against_the_resource_limit_by_priority(self):
        page = "https://shop.example.com/"
        imports = {page + "app.js": [(page, page + name) for name in ("c.js", "a-icons.js", "auth-config.js")]}
        rounds, _, output = self.run_with_imports(imports, limit=2)
        self.assertEqual(rounds, [[page + "app.js"], [page + "auth-config.js"]])
        self.assertIn("2 imported modules skipped by the URL limit", output)

    def test_import_chains_stop_after_the_round_limit(self):
        page = "https://shop.example.com/"
        chain = [page + f"m/{index}.js" for index in range(CLI["IMPORT_ROUNDS"] + 3)]
        imports = {page + "app.js": [(page, chain[0])]}
        imports.update({module: [(page, chain[index + 1])] for index, module in enumerate(chain[:-1])})
        rounds, _, output = self.run_with_imports(imports, limit=100)
        self.assertEqual(len(rounds), 1 + CLI["IMPORT_ROUNDS"])
        self.assertIn(f"1 imported modules not followed: imports nested deeper than {CLI['IMPORT_ROUNDS']} rounds", output)

    def test_partial_discovery_is_noted_when_the_report_is_written(self):
        main = CLI["main"]
        host = "shop.example.com"
        files_mock = Mock()
        files_mock.return_value.get_domains.return_value = [host]
        partial = QueryResult("RapidDNS", host, 100, frozenset([host]), available=10891)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(CLI["utils"], "get_workers", return_value=1))
            stack.enter_context(patch.object(CLI["utils"], "configure_platform_settings"))
            stack.enter_context(patch.dict(main.__globals__, {
                "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=10),
                "ManageFiles": files_mock, "create_pool": ThreadPool, "scan_subdomain_report": lambda domains: [partial],
                "process_chunks_for_internallinks": lambda args: ([], [], set(), [], {}),
            }))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertLogs(level="INFO") as logs:
                self.assertEqual(main(), 0)
        output = "\n".join(logs.output)
        self.assertIn("Report written with partial discovery", output)
        self.assertNotIn("incomplete discovery", output)

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
            return links, [], set(), [], {}

        def page_worker(args):
            seen_pages.extend(args[0])
            return [], set(), [], {}

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

    def test_every_url_is_requested_once_including_start_pages(self):
        # The link stage reads each start page; the page stage must not request it again.
        main = CLI["main"]
        host = "shop.example.com"
        start = f"https://{host}/"
        synthetic_value = "SYNTHETIC" + "FIXTURE" * 2
        for linked_page in (True, False):
            site = {
                start: ('<a href="/about">About</a>' if linked_page else "")
                       + f'<script src="/app.js"></script><script>api_key = "{synthetic_value}";</script>',
                start + "about": '<script src="/about.js"></script>',
                start + "app.js": "console.log(1);",
                start + "about.js": "console.log(2);",
            }
            requested = Counter()

            def get(url, **kwargs):
                requested[url] += 1
                manager = MagicMock()
                manager.__aenter__.return_value = http_response(200, site[url], {"Content-Type": "text/html"})
                return manager

            with self.subTest(linked_page=linked_page), TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(files, "OUTPUT_DIRECORY", Path(tmp)))
                stack.enter_context(patch.object(files.ManageFiles, "get_domains", return_value=[host]))
                stack.enter_context(patch.object(CLI["utils"], "get_workers", return_value=1))
                stack.enter_context(patch.object(CLI["utils"], "configure_platform_settings"))
                stack.enter_context(patch("aiohttp.ClientSession.get", new=Mock(side_effect=get)))
                stack.enter_context(patch.dict(main.__globals__, {
                    "time": Mock(perf_counter=time.perf_counter), "parse_arguments": lambda: Mock(limit=10),
                    "create_pool": ThreadPool, "scan_subdomain_report": lambda domains: [QueryResult("crt.sh", host, 0)],
                }))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                with self.assertLogs(level="INFO"):
                    self.assertEqual(main(), 0)
                report, = Path(tmp).glob("*.csv")
                with report.open(encoding="utf-8", newline="") as stream:
                    _, *rows = csv.reader(stream, delimiter=";")
                expected = [start, start + "app.js"] + ([start + "about", start + "about.js"] if linked_page else [])
                self.assertEqual(requested, Counter(expected))
                self.assertEqual([row[:2] for row in rows], [[start.rstrip("/"), start.rstrip("/")]])

    def test_page_and_resource_stages_use_every_worker_without_sampling_requests(self):
        main = CLI["main"]
        utils = CLI["utils"]
        host = "shop.example.com"
        pages = [f"https://{host}/p/{i}" for i in range(9)]
        page_chunks, resource_chunks = [], []

        def page_worker(args):
            page_chunks.append(list(args[0]))
            return [utils.ScrapNetworkUrls(page, page + ".js") for page in args[0]], set(), [], {}

        def resource_worker(arg):
            resource_chunks.append(list(arg[0]))
            return [], {}, []

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
                "process_chunks_for_internallinks": lambda args: (pages, [], set(), [], {}),
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
                "process_chunks_for_internallinks": remember(([page], [], set(), [], {})),
                "process_chunks_for_networksearch": remember(([utils.ScrapNetworkUrls(page, page + "app.js")], set(), [], {})),
                "process_chunks_for_credentialsearch": remember(([], {}, [])),
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
                    [page], [], set(), [], {"ok": 1, "redirect skipped": 2, "connect timeout": 3}),
                "process_chunks_for_networksearch": lambda args: (
                    [utils.ScrapNetworkUrls(page, page + "app.js")], set(), [], {"ok": 1}),
                "process_chunks_for_credentialsearch": lambda args: ([], {"ok": 4, "HTTP 429": 5}, []),
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

    def test_error_pages_and_bot_challenges_are_not_reported_as_ok(self):
        log_outcomes = CLI["_log_outcomes"]
        with self.assertLogs(level="INFO") as logs:
            log_outcomes("Network resource scan", Counter({
                "ok": 5, "truncated": 1, "HTTP 403 read": 2, "HTTP 404 read": 1, "bot challenge": 3}))
        self.assertEqual([(record.getMessage(), record.levelname) for record in logs.records], [(
            "Network resource scan requests: ok=6 (truncated=1), error status=3 (HTTP 403=2, HTTP 404=1), "
            "skipped=3 (bot challenge=3)", "WARNING")])

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
        priorities.return_value.prioritize_urls.side_effect = lambda urls, limit, scope=(): urls
        with contextlib.ExitStack() as stack:
            for signum in (signal.SIGINT, signal.SIGTERM):
                stack.callback(signal.signal, signum, signal.getsignal(signum))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(patch.dict(main.__globals__, {
                "parse_arguments": Mock(), "time": Mock(), "utils": utils,
                "ManageFiles": files_mock, "create_pool": ThreadPool,
                "scan_subdomain_report": lambda domains: [],
                "process_chunks_for_internallinks": lambda _: (["https://example.invalid/"], [], set(), [], {}),
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
