import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from printerhmi_agent.cli import main
from printerhmi_agent.enrollment import (
    EnrollmentStore,
    create_relay_challenge,
    verify_challenge_response,
)


class RelayProtocolTests(unittest.TestCase):
    def test_protocol_schemas_are_valid_json_with_closed_documents(self):
        root = Path(__file__).resolve().parents[1]
        for name in (
            "relay-challenge-v1.schema.json",
            "relay-enrollment-v1.schema.json",
        ):
            document = json.loads((root / "protocol" / name).read_text())
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertTrue(document["oneOf"])

    def test_cli_signs_a_relay_challenge_from_json_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            previous = os.environ.get("PRINTERHMI_ENROLLMENT_DIR")
            os.environ["PRINTERHMI_ENROLLMENT_DIR"] = temporary
            try:
                store = EnrollmentStore(Path(temporary))
                identity = store.identity()
                challenge = create_relay_challenge(
                    identity["device_id"], "relay-cli-test"
                )
                request = Path(temporary) / "challenge.json"
                request.write_text(json.dumps(challenge), encoding="utf-8")
                output = io.StringIO()
                with redirect_stdout(output):
                    result = main([
                        "enrollment", "challenge-sign", "--request", str(request)
                    ])
                self.assertEqual(result, 0)
                response = json.loads(output.getvalue())
                self.assertEqual(verify_challenge_response(response), challenge)
            finally:
                if previous is None:
                    os.environ.pop("PRINTERHMI_ENROLLMENT_DIR", None)
                else:
                    os.environ["PRINTERHMI_ENROLLMENT_DIR"] = previous


if __name__ == "__main__":
    unittest.main()
