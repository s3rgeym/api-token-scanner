#!/usr/bin/env python
from __future__ import annotations

import argparse
import asyncio
import collections
import dataclasses
import json
import logging
import re
import sys
import urllib.parse as uparse
from contextlib import asynccontextmanager, suppress
from email.message import Message as EmailMessage
from typing import Any, AsyncIterator, Iterator, NamedTuple, Sequence, TextIO

import aiohttp

# try:
#     import lxml  # noqa: F401
# except ImportError:
#     warnings.warn("lxml is not installed")


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
HTTP_REFERER = "https://www.google.com"


# access_token,refresh_token
TOKEN_NAME = (
    r"[\w\.-]*(?:"
    + "|".join(
        re.escape(x).replace("_", "_?") for x in ["token", "api_key", "client_secret"]
    )
    + ")"
)

TOKEN_VALUE = r"[\w-]{30,}"

TOKEN_RE = re.compile(
    "|".join(
        [
            rf"(?P<query_param>[^\"']+{TOKEN_NAME}={TOKEN_VALUE}[^\"']*)",
            rf"(?P<variable>{TOKEN_NAME}\s*=\s*[\"']{TOKEN_VALUE}[\"'])",
            rf"(?P<property>{TOKEN_NAME}['\"]?\s*:\s*['\"]{TOKEN_VALUE}[\"'])",
        ]
    ),
    re.IGNORECASE,
)

EXCLUDE_EXTS = (
    ".css",
    ".scss",
    ".less",
    ".map",
    ".jpeg",
    ".jpg",
    ".png",
    ".gif",
    ".bmp",
    ".mp3",
    ".wav",
    ".webm",
    ".avi",
    ".ogg",
    ".mov",
    ".qt",
    ".avi",
    ".mp4",
    ".pdf",
    ".doc",
    ".docx",
    ".xlsx",
    ".txt",
    ".csv",
    ".zip",
    ".rar",
    ".tar.gz",
    ".exe",
    ".dll",
    ".bin",
    ".apk",
)

LINK_RE = re.compile(r"<(?:a[^>]+href|script[^>]+src)=\"([^\"]+)", re.IGNORECASE)


class ANSI:
    CSI = "\x1b["
    RESET = f"{CSI}m"
    CLEAR_LINE = f"{CSI}2K\r"
    BLACK = f"{CSI}30m"
    RED = f"{CSI}31m"
    GREEN = f"{CSI}32m"
    YELLOW = f"{CSI}33m"
    BLUE = f"{CSI}34m"
    MAGENTA = f"{CSI}35m"
    CYAN = f"{CSI}36m"
    WHITE = f"{CSI}37m"


class ColorHandler(logging.StreamHandler):
    LEVEL_COLORS = {
        logging.DEBUG: ANSI.GREEN,
        logging.INFO: ANSI.YELLOW,
        logging.WARNING: ANSI.MAGENTA,
        logging.ERROR: ANSI.RED,
        logging.CRITICAL: ANSI.RED,
    }

    _fmt = logging.Formatter("[%(asctime)s] %(levelname)8s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        message = self._fmt.format(record)
        return f"{self.LEVEL_COLORS[record.levelno]}{message}{ANSI.RESET}"


logger = logging.getLogger(__name__)


class FoundToken(NamedTuple):
    type: str
    match: str


class Queue(asyncio.Queue):
    def _put(self, item: Any) -> None:
        """добавляет элементы наверх, а не в конец"""
        self._queue.appendleft(item)


@dataclasses.dataclass
class ApiTokenScanner:
    output: TextIO = sys.stdout
    _: dataclasses.KW_ONLY
    depth: int = 1
    concurrency: int = 50
    timeout: float = 5.0
    urls_per_host: int = 100

    @asynccontextmanager
    async def get_client_session(self) -> AsyncIterator[aiohttp.ClientSession]:
        resolver = aiohttp.AsyncResolver(nameservers=["8.8.8.8", "8.8.4.4"])
        conn = aiohttp.TCPConnector(
            limit=self.concurrency,
            ssl=False,
            ttl_dns_cache=300,
            use_dns_cache=True,
            keepalive_timeout=60,
            resolver=resolver,
        )
        # tmt = aiohttp.ClientTimeout(self.timeout)
        async with aiohttp.ClientSession(
            connector=conn,
            # тормозят куки?
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as client:
            client.headers.update(
                {
                    "User-Agent": USER_AGENT,
                    "Referer": HTTP_REFERER,
                }
            )
            yield client

    async def run(self, urls: Sequence[str]) -> None:
        self.q = Queue()

        for x in reversed(urls):
            self.q.put_nowait((x, self.depth))

        self.seen = set()
        self.counter = collections.Counter()

        async with asyncio.TaskGroup() as tg, self.get_client_session() as self.session:
            for _ in range(self.concurrency):
                tg.create_task(self.worker())

            await self.shutdown()

        logger.info("all tasks finished!")

    async def shutdown(self) -> None:
        await self.q.join()

        for _ in range(self.concurrency):
            self.q.put_nowait((None, 0))

    async def worker(self) -> None:
        while True:
            try:
                logger.debug(f"queue size: {self.q.qsize()}")

                url, depth = await self.q.get()

                try:
                    if url is None:
                        logger.info("task finished!")
                        break

                    if url in self.seen:
                        logger.debug(f"already seen: {url}")
                        continue

                    await self.handle_url(url, depth)
                finally:
                    self.q.task_done()
            # fix ERROR:asyncio:Task exception was never retrieved
            except (asyncio.CancelledError, KeyboardInterrupt):
                logger.warning("task canceled!")
                break

    async def handle_url(
        self,
        url: str,
        depth: int,
    ) -> None:
        logger.debug(f"start handle: {url} ({depth=})")
        try:
            async with asyncio.timeout(self.timeout), self.session.get(url) as response:
                self.seen.add(url)
                self.seen.add(str(response.url))
                response.raise_for_status()

                url = str(response.url)

                if (
                    content_length := int(response.headers.get("Content-Length", 0))
                ) == 0:
                    logger.warning(f"empty response body: {url}")
                    return

                if content_length > 100_000:
                    logger.warning(f"content-length too long: {url}")
                    return

                content_type = response.headers.get("Content-Type", "")
                content_type, _ = parse_content_type(content_type)

                # As of May 2022, text/javascript is the preferred type once again (see RFC 9239)
                # https://stackoverflow.com/a/73542396/2240578
                if content_type not in [
                    "text/html",
                    "application/javascript",
                    "text/javascript",
                ]:
                    logger.warning("unexpected content-type: %s", content_type)
                    return

                logger.debug(f"read contents: {url}")
                content = await response.text()

                if (
                    content_type == "text/html"
                    and depth > 0
                    and self.urls_per_host > self.counter[uparse.urlsplit(url).netloc]
                ):
                    logger.debug(f"collect links: {url}")
                    await self.collect_links(content, url, depth - 1)

                logger.debug(f"find tokens: {url}")

                for res in self.find_tokens(content):
                    json.dump(
                        res._asdict() | {"url": url},
                        self.output,
                        ensure_ascii=False,
                    )
                    self.output.write("\n")
                    self.output.flush()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            logger.warning(f"connection error: {url}")
        except Exception as ex:
            logger.exception(ex)
        else:
            logger.debug(f"successfully handle: {url}")

    def find_tokens(self, content: str) -> Iterator[FoundToken]:
        for m in TOKEN_RE.finditer(content):
            match_dict = m.groupdict()
            for k, v in match_dict.items():
                if v is not None:
                    yield FoundToken(k, v)
                    break

    def extract_links(self, content: str) -> list[str]:
        # тормозит
        # soup = BeautifulSoup(content, features="lxml")
        # rv = set()

        # for el in soup.find_all("a", href=True, download=False):
        #     rv.add(el["href"])

        # for el in soup.find_all("script", src=True):
        #     rv.add(el["src"])

        # return rv
        return LINK_RE.findall(content)

    async def collect_links(
        self,
        content: str,
        base_url: str,
        depth: int,
    ) -> None:
        # links = await asyncio.get_event_loop().run_in_executor(
        #     self.executor,
        #     self.extract_links,
        #     content,
        # )

        links = self.extract_links(content)

        base_netloc = uparse.urlsplit(base_url).netloc

        for link in links:
            url = uparse.urljoin(base_url, link)
            url, _ = uparse.urldefrag(url)

            if url in self.seen:
                continue

            sp = uparse.urlsplit(url)

            if base_netloc != sp.netloc:
                continue

            if sp.path.lower().endswith(EXCLUDE_EXTS):
                continue

            if self.counter[sp.netloc] + 1 > self.urls_per_host:
                logger.debug(f"limit exceeded urls per host: {sp.netloc}")
                return

            self.counter[sp.netloc] += 1
            await self.q.put((url, depth))


def parse_content_type(ct: str) -> tuple[str, dict[str, str]]:
    message = EmailMessage()
    message["Content-Type"] = ct
    params = message.get_params()
    return params[0][0], dict(params[1:])


def normalize_url(s: str) -> str:
    return s if "://" in s else "https://" + s


def main(argv: Sequence[str] | None = None) -> None:
    parser, args = _parse_args(argv)

    urls = list(map(normalize_url, filter(None, map(str.strip, args.input))))

    if not urls:
        parser.error("nothing to scan")

    lvl = max(logging.DEBUG, logging.WARNING - logging.DEBUG * args.verbose)
    logger.setLevel(level=lvl)
    logger.addHandler(ColorHandler())

    scanner = ApiTokenScanner(
        depth=args.depth,
        output=args.output,
        concurrency=args.concurrency,
        timeout=args.timeout,
        urls_per_host=args.urls_per_host,
    )

    with suppress(KeyboardInterrupt, asyncio.CancelledError):
        asyncio.run(scanner.run(urls))


class NameSpace(argparse.Namespace):
    input: TextIO
    output: TextIO
    depth: int
    concurrency: int
    timeout: float
    verbose: int
    urls_per_host: int


def _parse_args(
    argv: Sequence[str] | None,
) -> tuple[argparse.ArgumentParser, NameSpace]:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-i",
        "--input",
        "--in",
        help="input",
        type=argparse.FileType(),
        default="-",
    )
    parser.add_argument(
        "-o",
        "--output",
        "--out",
        help="output",
        type=argparse.FileType("w"),
        default="-",
    )
    parser.add_argument(
        "-d",
        "--depth",
        help="max crawling depth",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--urls-per-host",
        help="urls per host",
        type=int,
        default=100,
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        help="number of concurrent workers",
        type=int,
        default=50,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="client timeout",
        type=float,
        default=10.0,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="be more verbose (-vv for debug)",
        action="count",
        default=0,
    )
    return parser, parser.parse_args(argv, namespace=NameSpace())


if __name__ == "__main__":
    sys.exit(main())
