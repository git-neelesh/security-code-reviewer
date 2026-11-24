import unittest

from tools import (
    create_issue_dummy,
    get_commit_dummy,
    get_diff_dummy,
    get_file_contents_dummy,
    github_mcp_methods,
    list_commits_dummy,
)


class McpDummyFallbackTests(unittest.TestCase):
    def test_inventory_lists_mcp_and_dummy_methods(self):
        inventory = github_mcp_methods()
        names = {item["mcp_method"] for item in inventory["methods"]}
        self.assertIn("get_commit", names)
        self.assertIn("get_diff", names)
        self.assertIn("create_issue", names)

    def test_commit_dummy_has_success_status_and_source(self):
        result = get_commit_dummy("owner", "repo", "abc123")
        self.assertEqual(result["FETCH_STATUS"], "SUCCESS")
        self.assertEqual(result["source"], "dummy_fallback")

    def test_dummy_diff_file_and_commit_listing_need_no_network(self):
        diff = get_diff_dummy("owner", "repo", "abc123")
        content = get_file_contents_dummy("owner", "repo", "src/example.py", "abc123")
        commits = list_commits_dummy("owner", "repo")
        self.assertTrue(diff["diffs"])
        self.assertIn("Dummy", content["content"])
        self.assertEqual(commits["source"], "dummy_fallback")

    def test_issue_dummy_does_not_claim_remote_creation(self):
        result = create_issue_dummy("owner", "repo", "Security issue", "Body")
        self.assertEqual(result["source"], "dummy_fallback")
        self.assertIsNone(result["issue_number"])
        self.assertIsNone(result["url"])
        self.assertIn("no remote GitHub issue", result["message"])

    def test_fallback_methods_emit_warning_logs(self):
        with self.assertLogs("security_code_reviewer", level="WARNING") as logs:
            get_commit_dummy("owner", "repo", "abc123")
            get_diff_dummy("owner", "repo", "abc123")
            get_file_contents_dummy("owner", "repo", "src/example.py", "abc123")
            list_commits_dummy("owner", "repo")
            create_issue_dummy("owner", "repo", "Security issue", "Body")

        self.assertTrue(any("MCP fallback used" in message for message in logs.output))


if __name__ == "__main__":
    unittest.main()
