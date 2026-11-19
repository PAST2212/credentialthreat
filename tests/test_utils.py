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
