"""HTTP long-poll client for the Relay byte-pipe with keep-alive.
Два постоянных соединения: 'up' (/open,/up,/close) и 'down' (/down long-poll).
Убирает TLS-handshake на каждый запрос. HTTP вручную over asyncio streams.
"""
import asyncio
import json
import logging
import ssl
from urllib.parse import urlsplit, urlencode
from .config import get_outbound_proxy

log = logging.getLogger('tg-mtproto-proxy')

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


class RelayError(Exception):
    pass


class RelayTube:
    """send/recv over the Relay HTTP pipe (mimics a raw TCP socket to DC)."""
    OPEN_TIMEOUT = 10.0
    UP_TIMEOUT = 15.0
    DOWN_TIMEOUT = 35.0   # > server pollTimeout (25s)
    CLOSE_TIMEOUT = 5.0

    def __init__(self, base_url, token):
        u = urlsplit(base_url)
        if not u.hostname:
            raise RelayError(f"bad relay url: {base_url!r}")
        self.host = u.hostname
        self.token = token or ""
        self.sid = None
        self._up = None     # (reader, writer)
        self._down = None   # (reader, writer)

    def _q(self, extra):
        extra["tok"] = self.token
        return urlencode(extra)

    async def _conn(self, which):
        cur = self._up if which == 'up' else self._down
        if cur is not None:
            return cur
        proxy = get_outbound_proxy()
        if proxy:
            sock = await asyncio.wait_for(
                proxy.connect(self.host, 443), timeout=self.OPEN_TIMEOUT)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(sock=sock, ssl=_ssl_ctx,
                                        server_hostname=self.host),
                timeout=self.OPEN_TIMEOUT)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, 443, ssl=_ssl_ctx,
                                        server_hostname=self.host),
                timeout=self.OPEN_TIMEOUT)
        pair = (reader, writer)
        if which == 'up':
            self._up = pair
        else:
            self._down = pair
        return pair

    def _drop(self, which):
        pair = self._up if which == 'up' else self._down
        if which == 'up':
            self._up = None
        else:
            self._down = None
        if pair:
            try:
                pair[1].close()
            except Exception:
                pass

    async def _request(self, which, method, path, body, timeout):
        reader, writer = await self._conn(which)
        req = f"{method} {path} HTTP/1.1\r\nHost: {self.host}\r\nConnection: keep-alive\r\n"
        if body is not None:
            req += (f"Content-Length: {len(body)}\r\n"
                    f"Content-Type: application/octet-stream\r\n")
        else:
            req += "Content-Length: 0\r\n"
        req += "\r\n"
        writer.write(req.encode() + (body or b""))
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not status_line:
            raise ConnectionError("relay closed keep-alive connection")
        parts = status_line.split()
        status = int(parts[1]) if len(parts) >= 2 else 0
        content_length = None
        chunked = False
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if line in (b"\r\n", b"\n", b""):
                break
            low = line.lower()
            if low.startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1].strip())
            elif low.startswith(b"transfer-encoding:") and b"chunked" in low:
                chunked = True
        if chunked:
            chunks = []
            while True:
                size_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                chunk_size = int(size_line.strip(), 16)
                if chunk_size == 0:
                    await asyncio.wait_for(reader.readline(), timeout=timeout)
                    break
                chunk_data = await asyncio.wait_for(
                    reader.readexactly(chunk_size), timeout=timeout)
                chunks.append(chunk_data)
                await asyncio.wait_for(reader.readline(), timeout=timeout)
            resp_body = b"".join(chunks)
        elif content_length is not None:
            resp_body = await asyncio.wait_for(
                reader.readexactly(content_length), timeout=timeout)
        else:
            resp_body = b""
        return status, resp_body

    async def _request_retry(self, which, method, path, body, timeout):
        """Один ретрай при обрыве keep-alive (сервер закрыл простаивавшее соединение)."""
        try:
            return await self._request(which, method, path, body, timeout)
        except (ConnectionError, asyncio.IncompleteReadError, OSError) as e:
            log.debug("relay %s conn dropped (%r), reconnecting", which, e)
            self._drop(which)
            return await self._request(which, method, path, body, timeout)

    async def open(self, dst):
        status, body = await self._request_retry(
            'up', "GET", f"/open?{self._q({'dst': dst})}", None, self.OPEN_TIMEOUT)
        if status != 200:
            raise RelayError(f"open failed: HTTP {status} {body[:120]!r}")
        first_line = body.split(b'\n')[0].strip()
        self.sid = json.loads(first_line).get("sid")
        if not self.sid:
            raise RelayError(f"open: no sid in {body[:120]!r}")
        return self.sid

    async def send(self, data):
        if not self.sid:
            raise RelayError("send on closed tube")
        status, body = await self._request_retry(
            'up', "POST", f"/up?{self._q({'sid': self.sid})}", data, self.UP_TIMEOUT)
        if status != 200:
            raise RelayError(f"up failed: HTTP {status} {body[:120]!r}")

    async def recv(self):
        """Next bytes, or None when upstream closed. Hides 204 poll timeouts."""
        if not self.sid:
            return None
        while True:
            status, body = await self._request_retry(
                'down', "GET", f"/down?{self._q({'sid': self.sid})}", None, self.DOWN_TIMEOUT)
            if status == 200:
                return body
            if status == 204:
                continue
            if status == 410:
                return None
            raise RelayError(f"down failed: HTTP {status} {body[:120]!r}")

    async def close(self):
        if not self.sid:
            return
        sid, self.sid = self.sid, None
        try:
            await self._request_retry(
                'up', "POST", f"/close?{self._q({'sid': sid})}", None, self.CLOSE_TIMEOUT)
        except Exception as e:
            log.debug("relay close: %s", e)
        for which in ('up', 'down'):
            self._drop(which)