"""Doubles for the aiohttp response attributes the website fetcher reads: status, headers and content."""

from unittest.mock import MagicMock, Mock

from multidict import CIMultiDict, CIMultiDictProxy


class Stream:
    """Mirrors ClientResponse.content.iter_chunked and counts the chunks handed out."""

    def __init__(self, body: bytes):
        self.body = body
        self.reads = 0

    def iter_chunked(self, size):
        async def chunks():
            for start in range(0, len(self.body), size):
                self.reads += 1
                yield self.body[start:start + size]
        return chunks()


def response(status=200, body="", headers=None):
    data = body.encode("utf-8") if isinstance(body, str) else body
    return Mock(status=status, headers=CIMultiDictProxy(CIMultiDict(headers or {})), content=Stream(data))


def session_returning(*replies):
    """A session whose successive get() calls yield the given responses or raise the given errors."""
    managers = []
    for reply in replies:
        manager = MagicMock()
        if isinstance(reply, BaseException):
            manager.__aenter__.side_effect = reply
        else:
            manager.__aenter__.return_value = reply
        managers.append(manager)
    return Mock(get=Mock(side_effect=managers))


class FakeClock:
    """Monotonic clock whose sleep advances time instantly and records the pause."""

    def __init__(self):
        self.time = 0.0
        self.slept = []

    def now(self):
        return self.time

    async def sleep(self, seconds):
        self.slept.append(seconds)
        self.time += seconds
