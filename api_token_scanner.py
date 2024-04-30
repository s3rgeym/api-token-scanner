#!/usr/bin/env python
import argparse
import asyncio
import dataclasses
import json
import logging
import re
import sys
import urllib.parse as uparse
from collections import deque
from contextlib import asynccontextmanager, suppress
from email.message import Message as EmailMessage
from typing import AsyncIterator, Iterator, NamedTuple, Sequence, TextIO

import httpx
from bs4 import BeautifulSoup

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
HTTP_REFERER = "https://www.google.com"


# access_token,refresh_token
TOKEN_NAME = (
    r"[\w-]*(?:"
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

    _fmt = logging.Formatter("[%(levelname).1s] %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        message = self._fmt.format(record)
        return f"{self.LEVEL_COLORS[record.levelno]}{message}{ANSI.RESET}"


logger = logging.getLogger(__name__)


class FoundToken(NamedTuple):
    type: str
    match: str


@dataclasses.dataclass
class ApiTokenScanner:
    _: dataclasses.KW_ONLY
    depth: int = 1
    output: TextIO = sys.stdout
    parallel: int = 10
    timeout: float = 15.0

    def create_client(self) -> httpx.AsyncClient:
        client = httpx.AsyncClient(timeout=self.timeout, verify=False)
        client.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Referer": HTTP_REFERER,
            }
        )
        return client

    async def get_client(self) -> httpx.AsyncClient:
        while True:
            try:
                return self.clients.popleft()
            except IndexError:
                await asyncio.sleep(0.1)

    @asynccontextmanager
    async def acquire_client(self) -> AsyncIterator[httpx.AsyncClient]:
        client = await self.get_client()
        try:
            yield client
        finally:
            self.release_client(client)

    def release_client(self, client: httpx.AsyncClient) -> None:
        self.clients.appendleft(client)

    async def run(self, urls: Sequence[str]) -> None:
        q = asyncio.Queue()

        for x in urls:
            q.put_nowait((x, self.depth))

        self.create_clients()
        seen = set()

        tasks = [
            asyncio.create_task(self.worker(q, seen)) for _ in range(self.parallel)
        ]

        await q.join()

        for _ in range(self.parallel):
            q.put_nowait(None)

        await asyncio.wait(tasks)

        logger.info("all tasks finished!")

    # в aiohttp кидает ошибку, если не закрыть сессию
    # async def close_sessions(self) -> None:
    #     await asyncio.gather(
    #         *(s.close() for s in self.sessions), return_exceptions=True
    #     )

    async def worker(
        self, q: asyncio.Queue[tuple[str, int] | None], seen: set[str]
    ) -> None:
        while True:
            try:
                if (item := await q.get()) is None:
                    break

                url, depth = item

                if url in seen:
                    logger.debug(f"already seen: {url}")
                    continue

                async with self.acquire_client() as client:
                    await self.fetch(client, url, depth, q, seen)
            # fix ERROR:asyncio:Task exception was never retrieved
            except (asyncio.CancelledError, KeyboardInterrupt):
                break
            finally:
                q.task_done()

    async def fetch(
        self,
        client: httpx.AsyncClient,
        url: str,
        depth: int,
        q: asyncio.Queue[tuple[str, int] | None],
        seen: set[str],
    ) -> None:
        logger.debug(f"fetch: {url=}, {depth=}")

        try:
            response = await client.get(url)
            seen.add(str(response.url))
            # response.raise_for_status()
        except httpx.HTTPError as ex:
            logger.error(ex)
            return
        finally:
            seen.add(url)

        url = str(response.url)

        ct = response.headers.get("Content-Type", "")
        ct, _ = parse_content_type(ct)

        # As of May 2022, text/javascript is the preferred type once again (see RFC 9239)
        # https://stackoverflow.com/a/73542396/2240578
        # if ct not in [
        #     "text/html",
        #     "application/javascript",
        #     "text/javascript",
        # ]:
        #     logger.debug("unexpected content-type: %s", ct)
        #     return

        content = response.text

        if ct == "text/html" and depth > 0:
            links = self.extract_links(content)
            await self.process_links(links, url, depth - 1, q, seen)

        for res in self.find_tokens(content):
            json.dump(
                res._asdict() | {"url": url},
                self.output,
                ensure_ascii=False,
            )
            self.output.write("\n")
            self.output.flush()

    def find_tokens(self, content: str) -> Iterator[FoundToken]:
        for m in TOKEN_RE.finditer(content):
            match_dict = m.groupdict()
            for k, v in match_dict.items():
                if v is not None:
                    yield FoundToken(k, v)
                    break

    def extract_links(self, content: str) -> set[str]:
        soup = BeautifulSoup(content, features="lxml")
        links = set()

        for el in soup.find_all("a", href=True, download=False):
            links.add(el["href"])

        for el in soup.find_all("script", src=True):
            links.add(el["src"])

        return links

    async def process_links(
        self,
        links: set[str],
        base_url: str,
        depth: int,
        q: asyncio.Queue[tuple[str, int] | None],
        seen: set[str],
    ) -> None:
        sp = uparse.urlsplit(base_url)

        for link in links:
            url = uparse.urljoin(base_url, link)

            if sp.netloc != uparse.urlsplit(url).netloc:
                continue

            url, _ = uparse.urldefrag(url)

            if url in seen:
                continue

            logger.debug(f"add to queue: {url}")
            await q.put((url, depth))

    def create_clients(self) -> None:
        self.clients = deque(
            iterable=(self.create_client() for x in range(self.parallel)),
            maxlen=self.parallel,
        )


def parse_content_type(ct: str) -> tuple[str, dict[str, str]]:
    message = EmailMessage()
    message["Content-Type"] = ct
    params = message.get_params()
    return params[0][0], dict(params[1:])


def normalize_url(s: str) -> str:
    return s if "://" in s else "https://" + s


def main(argv: Sequence[str] | None = None) -> None:
    parser, args = _parse_args(argv)

    urls = set(map(normalize_url, filter(None, map(str.strip, args.input))))

    if not urls:
        parser.error("nothing to scan")

    lvl = max(logging.DEBUG, logging.WARNING - logging.DEBUG * args.verbose)
    logger.setLevel(level=lvl)
    logger.addHandler(ColorHandler())

    scanner = ApiTokenScanner(
        depth=args.depth,
        output=args.output,
        parallel=args.parallel,
        timeout=args.timeout,
    )

    with suppress(KeyboardInterrupt, asyncio.CancelledError):
        asyncio.run(scanner.run(urls))


class NameSpace(argparse.Namespace):
    input: TextIO
    output: TextIO
    depth: int
    parallel: int
    timeout: float
    verbose: int


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
        "-p",
        "--parallel",
        help="number of parallel tasks",
        type=int,
        default=10,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="client timeout",
        type=float,
        default=15.0,
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
