import unittest
from unittest.mock import patch

from credentialthreat.core import utils


def pick(urls, limit):
    with patch("logging.info"):
        return utils.UrlPrioritizer().prioritize_urls(urls, limit=limit)


class PrioritizerTests(unittest.TestCase):
    def test_script_files_outrank_other_low_priority_resources(self):
        urls = [("https://h.example.com/", "https://h.example.com/site.css"),
                ("https://h.example.com/", "https://h.example.com/static/main.js?v=3")]
        self.assertEqual(pick(urls, 1), [urls[1]])

    def test_patterns_written_as_expressions_match(self):
        self.assertEqual(pick(["https://www.example.com/about", "https://dev.example.com/"], 1),
                         ["https://dev.example.com/"])
        resources = [("https://h.example.com/", "https://h.example.com/a.css"),
                     ("https://h.example.com/", "https://h.example.com/elasticsearch.css")]
        self.assertEqual(pick(resources, 1), [resources[1]])

    def test_selection_under_a_limit_does_not_depend_on_input_order(self):
        urls = [f"https://www.example.com/p/{i}" for i in range(6)]
        self.assertEqual(pick(urls, 3), pick(list(reversed(urls)), 3))


class FinalSelectionLogTests(unittest.TestCase):
    # On one production site the log read `High Priority: 586 (100.0%)` for a selection with 141 high-priority URLs.
    def final_selection(self, urls, limit):
        with self.assertLogs(level="INFO") as logs:
            result = utils.UrlPrioritizer().prioritize_urls(urls, limit=limit)
        message, = [record.getMessage() for record in logs.records if "Final Selection" in record.getMessage()]
        return result, message

    def test_resources_are_counted_by_the_priority_they_were_selected_for(self):
        base = "https://h.example.com/"
        high = [(base, base + f"auth{i}.css") for i in range(2)]
        medium = [(base, base + f"app{i}.js") for i in range(3)]
        low = [(base, base + f"site{i}.css") for i in range(4)]
        result, message = self.final_selection(low + medium + high, limit=7)
        self.assertCountEqual(result, high + medium + low[:2])
        for line in ("Selected URLs: 7", "High Priority: 2 (28.6%)", "Medium Priority: 3 (42.9%)", "Low Priority: 2 (28.6%)"):
            self.assertIn(line, message)

    def test_pages_are_counted_by_the_priority_they_were_selected_for(self):
        high = ["https://dev.a.example.com/", "https://dev.b.example.com/"]
        low = [f"https://www.example.com/p/{i}" for i in range(4)]
        result, message = self.final_selection(low + high, limit=3)
        self.assertCountEqual(result, high + low[:1])
        for line in ("Selected URLs: 3", "High Priority: 2 (66.7%)", "Low Priority: 1 (33.3%)"):
            self.assertIn(line, message)


class HostConnectionBudgetTests(unittest.TestCase):
    def test_workers_together_never_open_more_than_the_host_budget(self):
        for workers in (1, 2, 5, 7, 11):
            with self.subTest(workers=workers):
                per_worker = utils.host_connections_per_worker(workers)
                self.assertLessEqual(per_worker * workers, 25)
                self.assertGreaterEqual(per_worker, 2)
        self.assertEqual(utils.host_connections_per_worker(1), 25)
        self.assertEqual(utils.host_connections_per_worker(5), 5)

    def test_many_workers_still_get_two_connections_each(self):
        self.assertEqual(utils.host_connections_per_worker(40), 2)


class ChunkPlanTests(unittest.TestCase):
    def test_each_worker_receives_one_chunk_with_every_item_once(self):
        # A chunk ends with its slowest request, so every extra chunk per worker adds an idle tail.
        chunks = utils.plan_chunks(list(range(4661)), workers=5)
        self.assertEqual(len(chunks), 5)
        self.assertEqual(sorted(item for chunk in chunks for item in chunk), list(range(4661)))
        sizes = {len(chunk) for chunk in chunks}
        self.assertLessEqual(max(sizes) - min(sizes), 1)

    def test_hosts_of_a_sorted_list_are_spread_over_all_chunks(self):
        urls = [f"https://a.example.com/{i}" for i in range(8)] + [f"https://b.example.com/{i}" for i in range(8)]
        for chunk in utils.plan_chunks(urls, workers=2):
            self.assertEqual({url.split("/")[2] for url in chunk}, {"a.example.com", "b.example.com"})

    def test_small_inputs_split_down_to_single_items(self):
        self.assertEqual(utils.plan_chunks(["a", "b", "c"], workers=5), [["a"], ["b"], ["c"]])

    def test_empty_input_produces_no_chunks(self):
        self.assertEqual(utils.plan_chunks([], workers=5), [])


if __name__ == "__main__":
    unittest.main()
