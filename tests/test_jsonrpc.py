import unittest

from agent_firewall.jsonrpc import (
    DuplicateKeys,
    decode_message,
    encode_message,
    request_key,
)


class JsonRpcFramingTests(unittest.TestCase):
    def test_duplicate_key_error_is_a_value_error(self):
        self.assertTrue(issubclass(DuplicateKeys, ValueError))

    def test_round_trip_preserves_unicode_and_compact_framing(self):
        message = {"jsonrpc": "2.0", "id": "é", "result": {"ok": True}}
        encoded = encode_message(message)
        self.assertEqual(encoded.count(b"\n"), 1)
        self.assertEqual(decode_message(encoded), message)

    def test_malformed_and_non_object_frames_are_not_messages(self):
        self.assertIsNone(decode_message(b"not json\n"))
        self.assertIsNone(decode_message(b"[]\n"))
        self.assertIsNone(decode_message(b"\xff\n"))

    def test_duplicate_keys_at_any_depth_are_rejected(self):
        for line in (
            b'{"jsonrpc":"2.0","id":1,"method":"m","method":"tools/call"}\n',
            b'{"jsonrpc":"2.0","id":1,"params":{"name":"t","name":"u"}}\n',
        ):
            with self.subTest(line=line):
                with self.assertRaisesRegex(ValueError, "duplicate key"):
                    decode_message(line)

    def test_nested_objects_without_duplicates_decode(self):
        message = decode_message(
            b'{"jsonrpc":"2.0","id":1,"params":{"name":"t","arguments":{"a":1}}}\n'
        )
        assert message is not None
        self.assertEqual(message["params"]["name"], "t")

    def test_request_keys_preserve_id_types(self):
        self.assertNotEqual(request_key(1), request_key("1"))


if __name__ == "__main__":
    unittest.main()
