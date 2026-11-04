import unittest
from pathlib import Path
import importlib.util

spec = importlib.util.spec_from_file_location("tool_runner", Path(__file__).resolve().parents[1] / "tools" / "runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def test_harvester_typed_data_does_not_label_arbitrary_text(self):
        data = {"emails": ["name@example.org"], "hosts": ["sub.example.org"], "ips": ["8.8.8.8", "invalid"], "comment": "name@example.org"}
        entities = runner.structured_entities(data)
        self.assertEqual({(x["type"], x["value"]) for x in entities}, {("email", "name@example.org"), ("domain", "sub.example.org"), ("ip", "8.8.8.8")})

    def test_sherlock_claimed_profiles_only(self):
        data = [{"url_user": "https://example.org/a", "exists": "True"}, {"url_user": "https://example.org/b", "exists": "False"}]
        result = runner.profile_entities(data)
        self.assertEqual([x["value"] for x in result], ["https://example.org/a"])
        self.assertFalse(result[0]["attributes"]["confirmed_owner"])

    def test_spiderfoot_module_event_is_preserved(self):
        result = runner.structured_entities([{"type": "Email Address", "data": "name@example.org", "module": "sfp_test"}])
        self.assertEqual(result[0]["type"], "email")
        self.assertEqual(result[0]["attributes"]["module"], "sfp_test")

    def test_phoneinfoga_exclusions_are_separate_array_arguments(self):
        command = runner.command(runner.Task(tool="phoneinfoga", kind="phone", value="+12025550123"), Path("."))
        self.assertEqual(command.count("--disable"), 2)
        self.assertNotIn("numverify,ovh", command)


if __name__ == "__main__":
    unittest.main()
