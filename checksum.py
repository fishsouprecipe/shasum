#! /usr/bin/python3

import sys
import argparse
import urllib.request
import hashlib
import ssl
import os.path

from typing import Any
from typing import Optional
from typing import Union
from typing import Dict
from typing import Callable
from typing import Tuple


KIBIBYTE: int = 1024
MEBIBYTE: int = 1024 * KIBIBYTE

DEFAULT_CAFILE_PATHS: Tuple[str, ...] = (
    "/etc/ssl/certs/cacert.pem",
    "/etc/ssl/cert.pem",
)
DEFAULT_USER_AGENT: str = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36")


def get_alogirthm_function(algorithm_version: int) -> Callable[[bytes], Any]:
    return getattr(hashlib, f"sha{algorithm_version}")


def get_hashsum(algorithm_version: int, b: bytes) -> str:
    return get_alogirthm_function(algorithm_version)(b).hexdigest()


def create_ssl_context(cafile: Optional[str]) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=cafile)


def get_headers(user_agent: str) -> Dict[str, str]:
    return {
        "User-Agent": user_agent
    }


def build_request(url: str, headers: Dict[str, str]) -> urllib.request.Request:
    return urllib.request.Request(url, headers=headers)


def read_bytes(readable: Any, chunk_size: int) -> bytes:
    b: bytes = b""
    while True:
        new_bytes: bytes = readable.read(chunk_size)

        if not new_bytes:
            break

        b += new_bytes

    return b


def read_file(path: str) -> bytes:
    with open(path, 'rb') as fp:
        b: bytes = read_bytes(fp, MEBIBYTE)

    return b


def read_request(request: urllib.request.Request, ssl_context: ssl.SSLContext) -> bytes:
    with urllib.request.urlopen(request, context=ssl_context) as fp:
        b: bytes = read_bytes(fp, 4 * KIBIBYTE)

    return b


def get_default_cafile() -> str:
    for cafile_path in DEFAULT_CAFILE_PATHS:
        if os.path.exists(cafile_path):
            return cafile_path

    raise FileNotFoundError("Cannot find any cafile")


def main() -> int:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="Checking sum of url")
    parser.add_argument("-T", "--target", type=str, help="URL or path", required=True)
    parser.add_argument("-A", "--algorithm-version", type=int, default=1, help="SHA algorithm version, 1 default", required=False)
    parser.add_argument("-U", "--user-agent", type=str, default=DEFAULT_USER_AGENT, help="User Agent, used only if target is url", required=False)
    parser.add_argument("-C", "--cafile", type=str, help="Cafile path, used only if target is url startswith https", required=False)
    parser.add_argument("-H", "--hashsum", type=str, help="Hashsum", required=False)
    args: argparse.Namespace = parser.parse_args()

    target: str = args.target
    algorithm_version: int = args.algorithm_version

    user_agent: str = args.user_agent
    cafile: Optional[str] = args.cafile

    hashsum: Optional[str] = args.hashsum

    if target.startswith("http"):
        headers: Dict[str, str] = get_headers(user_agent)
        request: urllib.request.Request = build_request(target, headers)

        if not cafile:
            cafile = get_default_cafile()

        ssl_context: ssl.SSLContext = create_ssl_context(cafile)

        b: bytes = read_request(request, ssl_context)

    else:
        b = read_file(target)

    target_hashsum: str = get_hashsum(algorithm_version, b)

    if hashsum is None:
        print(f"Target hassum is {target_hashsum!r}")

        return 0

    if target_hashsum == hashsum:
        print(True)

        return 0

    print(False)

    return 1


if __name__ == "__main__":
    sys.exit(main())
