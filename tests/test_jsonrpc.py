import unittest

from agent_firewall.jsonrpc import decode_message, encode_message, request_key


class JsonRpcFramingTests(unittest.TestCase):
    def test_round_trip_preserves_unicode_and_compact_framing(self):
        message = {"jsonrpc": "2.0", "id": "é", "result": {"ok": True}}
        encoded = encode_message(message)
        self.assertEqual(encoded.count(b"\n"), 1)
        self.assertEqual(decode_message(encoded), message)

    def test_malformed_and_non_object_frames_are_not_messages(self):
        self.assertIsNone(decode_message(b"not json\n"))
        self.assertIsNone(decode_message(b"[]\n"))
        self.assertIsNone(decode_message(b"\xff\n"))

    def test_request_keys_preserve_id_types(self):
        self.assertNotEqual(request_key(1), request_key("1"))


if __name__ == "__main__":
    unittest.main()
