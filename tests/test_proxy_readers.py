"""Regression tests for the proxy's bounded line readers.

Both readers must return exactly one newline-terminated line per call and
must never lose bytes that follow an oversized line or a line that shares a
transport chunk.
"""

import asyncio
import io
import unittest

from agent_firewall.mcp_proxy import _read_child_line, _read_line


class SyncReadLineTests(unittest.TestCase):
    def test_returns_one_line_per_call(self):
        stream = io.BytesIO(b"first\nsecond\nthird\n")
        self.assertEqual(_read_line(stream, 1024), (b"first\n", False))
        self.assertEqual(_read_line(stream, 1024), (b"second\n", False))
        self.assertEqual(_read_line(stream, 1024), (b"third\n", False))
        self.assertEqual(_read_line(stream, 1024), (b"", False))

    def test_oversized_line_is_drained_and_following_lines_survive(self):
        stream = io.BytesIO(b"x" * 2000 + b"\n" + b"after\n")
        self.assertEqual(_read_line(stream, 1024), (b"", True))
        self.assertEqual(_read_line(stream, 1024), (b"after\n", False))

    def test_oversized_line_without_newline_at_eof(self):
        stream = io.BytesIO(b"x" * 2000)
        self.assertEqual(_read_line(stream, 1024), (b"", True))
        self.assertEqual(_read_line(stream, 1024), (b"", False))

    def test_line_exactly_at_limit_is_accepted(self):
        stream = io.BytesIO(b"a" * 1023 + b"\n")
        self.assertEqual(_read_line(stream, 1024), (b"a" * 1023 + b"\n", False))

    def test_empty_stream(self):
        stream = io.BytesIO(b"")
        self.assertEqual(_read_line(stream, 1024), (b"", False))


class AsyncReadChildLineTests(unittest.IsolatedAsyncioTestCase):
    def _stream(self, data):
        stream = asyncio.StreamReader()
        stream.feed_data(data)
        stream.feed_eof()
        return stream

    def _reader(self):
        return asyncio.StreamReader()

    def setUp(self):
        self.remainder = bytearray()

    async def _read(self, stream, limit=1024):
        line, oversized, self.remainder = await _read_child_line(
            stream, limit, self.remainder
        )
        return line, oversized

    async def test_multiple_lines_in_one_chunk_are_split(self):
        stream = self._stream(b"first\nsecond\nthird\n")
        self.assertEqual(await self._read(stream), (b"first\n", False))
        self.assertEqual(await self._read(stream), (b"second\n", False))
        self.assertEqual(await self._read(stream), (b"third\n", False))
        self.assertEqual(await self._read(stream), (b"", False))

    async def test_line_split_across_chunks(self):
        stream = self._stream(b"first ha" + b"lf\nrest\n")
        self.assertEqual(await self._read(stream), (b"first half\n", False))
        self.assertEqual(await self._read(stream), (b"rest\n", False))

    async def test_oversized_line_drains_and_keeps_following_lines(self):
        stream = self._stream(b"x" * 2000 + b"\n" + b"after\n" + b"final\n")
        self.assertEqual(await self._read(stream, limit=1024), (b"", True))
        self.assertEqual(await self._read(stream), (b"after\n", False))
        self.assertEqual(await self._read(stream), (b"final\n", False))

    async def test_oversized_line_and_response_in_one_drain(self):
        stream = self._stream(b"x" * 2000 + b"\n" + b'{"id":1}\n')
        self.assertEqual(await self._read(stream, limit=1024), (b"", True))
        self.assertEqual(await self._read(stream), (b'{"id":1}\n', False))

    async def test_oversized_line_without_newline_at_eof(self):
        stream = self._stream(b"x" * 2000)
        self.assertEqual(await self._read(stream, limit=1024), (b"", True))

    async def test_line_at_limit_is_accepted(self):
        stream = self._stream(b"a" * 1023 + b"\n" + b"next\n")
        line, oversized = await self._read(stream, limit=1024)
        self.assertEqual((line, oversized), (b"a" * 1023 + b"\n", False))
        self.assertEqual(await self._read(stream), (b"next\n", False))

    async def test_byte_at_a_time_delivery(self):
        stream = self._reader()
        for byte in b"line one\nline two\n":
            stream.feed_data(bytes([byte]))
        stream.feed_eof()
        self.assertEqual(await self._read(stream), (b"line one\n", False))
        self.assertEqual(await self._read(stream), (b"line two\n", False))

    async def test_child_exiting_after_responding_does_not_crash(self):
        """The child's transport delivers data then EOF; the reader must not
        try to re-feed bytes into a closed stream."""
        stream = self._reader()
        stream.feed_data(b'{"jsonrpc":"2.0","id":"a:1","result":{}}\n')
        stream.feed_data(b'{"jsonrpc":"2.0","id":"a:2","result":{}}\n')
        stream.feed_eof()
        line, oversized, self.remainder = await _read_child_line(
            stream, 1024, self.remainder
        )
        self.assertEqual(
            (line, oversized), (b'{"jsonrpc":"2.0","id":"a:1","result":{}}\n', False)
        )
        line, oversized, self.remainder = await _read_child_line(
            stream, 1024, self.remainder
        )
        self.assertEqual(
            (line, oversized), (b'{"jsonrpc":"2.0","id":"a:2","result":{}}\n', False)
        )


if __name__ == "__main__":
    unittest.main()
