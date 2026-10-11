from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse, urlunparse

import requests
import yaml


DEFAULT_API_BASE_URLS = (
    "https://fbesa.apiv2.a047.com/api/v1",
    "https://fbapi.web.ak005.com",
    "https://fbapi.apiv2.a047.com",
)
DEFAULT_USER_AGENT = "ua.net.fbclient.android/1.33.14(1)"
DEFAULT_ACCEPT_LANGUAGE = "zh-CN,zh-Hans;q=0.9"
LOGIN_PATH = "/api/v1/passport/auth/login"
SUBSCRIBE_INFO_PATH = "/api/v1/user/getSubscribe"
SUPPORTED_URI_SCHEMES = {
    "ss",
    "ssr",
    "vmess",
    "vless",
    "trojan",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "wireguard",
}


class FetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class DecodedSubscription:
    format: str
    text: str
    nodes: list[Any]
    node_types: dict[str, int]
    decode_layers: int


def find_default_android_reference(workspace: Path) -> Path:
    candidates: list[Path] = []
    live_path = workspace / "getSubscribe_live.json"
    if live_path.is_file():
        candidates.append(live_path)
    outputs_path = workspace / "outputs"
    if outputs_path.is_dir():
        candidates.extend(
            path
            for path in outputs_path.rglob("*getSubscribe*.json")
            if path.is_file()
        )
    if not candidates:
        return live_path
    return max(candidates, key=lambda path: path.stat().st_mtime)


def normalize_base_url(value: str) -> str:
    parsed = urlparse(value.strip().rstrip("/"))
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("API base URL must be an absolute HTTPS URL.")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def safe_endpoint(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def api_url(base_url: str, api_path: str) -> str:
    parsed = urlparse(base_url)
    base_path = parsed.path.rstrip("/")
    normalized_api_path = "/" + api_path.lstrip("/")
    if base_path.endswith("/api/v1") and normalized_api_path.startswith("/api/v1/"):
        joined_path = base_path + normalized_api_path[len("/api/v1") :]
    else:
        joined_path = base_path + normalized_api_path
    return urlunparse((parsed.scheme, parsed.netloc, joined_path, "", "", ""))


def sanitize_message(message: str, secrets: tuple[str, ...] = ()) -> str:
    result = re.sub(r"([?&]token=)[^&\s'\"]+", r"\1<redacted>", message, flags=re.IGNORECASE)
    result = re.sub(
        r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "<redacted-jwt>",
        result,
    )
    for secret in secrets:
        if secret:
            result = result.replace(secret, "<redacted>")
    return result


def get_json_field(obj: Any, paths: tuple[str, ...]) -> str | None:
    for path in paths:
        current = obj
        for segment in path.split("."):
            if not isinstance(current, dict) or segment not in current:
                break
            current = current[segment]
        else:
            if current is not None and str(current).strip():
                return str(current)
    return None


def inspect_subscription_link(url: str) -> dict[str, Any]:
    """Return non-secret metadata for a subscription URL.

    The raw URL is retained only in the returned in-memory dictionary so the
    caller can perform an exact comparison.  It is deliberately never copied
    into an output summary or log line.
    """
    raw_url = str(url).strip()
    parsed = urlparse(raw_url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise FetchError("Subscription link must be an absolute HTTPS URL.")
    if parsed.username or parsed.password:
        raise FetchError("Subscription link must not contain URL credentials.")

    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    token_values = [value for key, value in query_items if key.lower() == "token"]
    if len(token_values) != 1 or not token_values[0]:
        raise FetchError("Subscription link did not contain exactly one non-empty token.")

    token = token_values[0]
    return {
        "raw_url": raw_url,
        "endpoint": safe_endpoint(raw_url),
        "url_length": len(raw_url),
        "token_length": len(token),
        "url_sha256": hashlib.sha256(raw_url.encode("utf-8")).hexdigest(),
        "query_keys": sorted({key for key, _ in query_items}),
    }


def read_subscription_url_from_json_file(path: Path, label: str) -> str:
    if not path.is_file():
        raise FetchError(f"{label} was not found: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise FetchError(f"{label} is not valid JSON: {path}") from exc
    url = get_json_field(
        document,
        (
            "data.subscribe_url",
            "data.subscription_url",
            "data.subscribeUrl",
            "data.url",
            "subscribe_url",
            "subscription_url",
            "subscribeUrl",
            "url",
        ),
    )
    if not url:
        raise FetchError(f"{label} did not contain a subscription URL: {path}")
    inspect_subscription_link(url)
    return url.strip()


def read_desktop_cached_subscription_url(path: Path) -> str:
    if not path.is_file():
        raise FetchError(f"FlyingBird desktop preferences were not found: {path}")
    try:
        preferences = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise FetchError(f"FlyingBird desktop preferences are not valid JSON: {path}") from exc

    cached_info = preferences.get("flutter.cached_subscribe_info") if isinstance(preferences, dict) else None
    if isinstance(cached_info, str):
        try:
            cached_info = json.loads(cached_info)
        except (ValueError, json.JSONDecodeError) as exc:
            raise FetchError("FlyingBird desktop cached subscription metadata is not valid JSON.") from exc
    if not isinstance(cached_info, (dict, list)):
        raise FetchError("FlyingBird desktop preferences did not contain cached subscription metadata.")

    url = get_json_field(
        cached_info,
        (
            "subscribe_url",
            "subscription_url",
            "subscribeUrl",
            "url",
        ),
    )
    if not url:
        raise FetchError("FlyingBird desktop cached subscription metadata did not contain a URL.")
    inspect_subscription_link(url)
    return url.strip()


def verify_android_subscription_link(
    args: argparse.Namespace,
    observed_url: str,
    observed_label: str,
    observed_path: Path | None = None,
) -> dict[str, Any]:
    """Require an observed link to exactly match the Android getSubscribe link."""
    reference_path = Path(args.android_getsubscribe_json).expanduser().resolve()
    reference_url = read_subscription_url_from_json_file(reference_path, "Android getSubscribe reference")
    reference = inspect_subscription_link(reference_url)
    observed = inspect_subscription_link(observed_url)
    if reference["raw_url"] != observed["raw_url"]:
        raise FetchError(f"Android subscription link did not exactly match {observed_label}.")

    reference_stat = reference_path.stat()
    details: dict[str, Any] = {
        "subscription_provenance": "android-link-verified",
        "android_reference_file": str(reference_path),
        "android_reference_updated_utc": datetime.fromtimestamp(
            reference_stat.st_mtime, timezone.utc
        ).isoformat(timespec="seconds"),
        "android_link_endpoint": reference["endpoint"],
        "android_link_sha256": reference["url_sha256"],
        "android_link_length": reference["url_length"],
        "android_token_length": reference["token_length"],
        "verified_link_source": observed_label,
        "verified_link_endpoint": observed["endpoint"],
        "verified_link_sha256": observed["url_sha256"],
        "verified_link_length": observed["url_length"],
        "verified_token_length": observed["token_length"],
        "link_comparison": "exact",
        "link_match": True,
    }
    if observed_path is not None:
        details["verified_link_file"] = str(observed_path)
    return details


def replace_host(url: str, host: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(netloc=host))


def subscribe_url_candidates(subscribe_url: str, base_url: str) -> list[str]:
    parsed_subscribe = urlparse(subscribe_url)
    parsed_base = urlparse(base_url)
    if parsed_subscribe.scheme != "https" or not parsed_subscribe.hostname:
        raise FetchError("Subscription response did not contain a valid HTTPS URL.")

    base_host = parsed_base.netloc
    candidates: list[str] = []
    placeholder = bool(re.search(r"(^|\.)example\.com$", parsed_subscribe.hostname, re.IGNORECASE))

    if placeholder:
        candidates.append(replace_host(subscribe_url, base_host))
    else:
        candidates.append(subscribe_url)

    if base_host.startswith("fbapi."):
        candidates.append(replace_host(subscribe_url, base_host.replace("fbapi.", "fbapid.", 1)))
    elif base_host.startswith("fbapid."):
        candidates.append(replace_host(subscribe_url, base_host.replace("fbapid.", "fbapi.", 1)))

    if not placeholder:
        candidates.append(subscribe_url)

    result: list[str] = []
    for candidate in candidates:
        if candidate not in result:
            result.append(candidate)
    return result


def request_json(
    session: requests.Session,
    method: str,
    url: str,
    headers: dict[str, str],
    timeout: float,
    json_body: dict[str, str] | None = None,
) -> tuple[int, Any]:
    try:
        response = session.request(
            method,
            url,
            headers=headers,
            json=json_body,
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise FetchError(
            f"{method} {safe_endpoint(url)} transport failure ({type(exc).__name__})."
        ) from exc

    if not 200 <= response.status_code < 300:
        raise FetchError(f"{method} {safe_endpoint(url)} returned HTTP {response.status_code}.")
    try:
        return response.status_code, response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise FetchError(f"{method} {safe_endpoint(url)} returned invalid JSON.") from exc


def decode_base64_layer(text: str) -> bytes | None:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 16 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return None
    padding = "=" * (-len(compact) % 4)
    try:
        decoded = base64.b64decode(compact + padding, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    return decoded if decoded else None


def parse_yaml_nodes(text: str) -> DecodedSubscription | None:
    if not re.search(r"(?m)^\s*proxies\s*:", text):
        return None
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(document, dict) or not isinstance(document.get("proxies"), list):
        return None

    nodes = document["proxies"]
    types = Counter(
        str(node.get("type", "unknown")).lower()
        for node in nodes
        if isinstance(node, dict)
    )
    return DecodedSubscription("mihomo-yaml", text, nodes, dict(sorted(types.items())), 0)


def parse_uri_nodes(text: str) -> DecodedSubscription | None:
    nodes: list[str] = []
    types: Counter[str] = Counter()
    for line in text.splitlines():
        candidate = line.strip()
        match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", candidate)
        if not match:
            continue
        scheme = match.group(1).lower()
        if scheme not in SUPPORTED_URI_SCHEMES:
            continue
        nodes.append(candidate)
        types[scheme] += 1

    if not nodes:
        return None
    return DecodedSubscription("uri-list", text, nodes, dict(sorted(types.items())), 0)


def decode_subscription(content: bytes, max_layers: int = 3) -> DecodedSubscription:
    current = content
    for layer in range(max_layers + 1):
        try:
            text = current.decode("utf-8-sig").strip()
        except UnicodeDecodeError:
            text = ""

        if text:
            parsed = parse_yaml_nodes(text) or parse_uri_nodes(text)
            if parsed:
                return DecodedSubscription(
                    parsed.format,
                    parsed.text,
                    parsed.nodes,
                    parsed.node_types,
                    layer,
                )
            decoded = decode_base64_layer(text)
            if decoded is not None and decoded != current:
                current = decoded
                continue
        break

    raise FetchError("Downloaded subscription did not decode to Mihomo YAML or a supported URI list.")


def atomic_write(path: Path, data: bytes, sensitive: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        if sensitive:
            os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temporary, path)
        temporary = None
        if sensitive:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def common_headers(user_agent: str, accept_language: str, authorization: str | None = None) -> dict[str, str]:
    headers = {
        "accept": "*/*",
        "accept-language": accept_language,
        "user-agent": user_agent,
    }
    if authorization:
        headers["authorization"] = authorization
    return headers


def read_x_auth_from_go_source(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r'(?m)^\s*defaultXAuth\s*=\s*"([^"]+)"', source)
    return match.group(1).strip() if match and match.group(1).strip() else None


def resolve_x_auth_token() -> tuple[str | None, str | None]:
    environment_value = os.environ.get("FLYINGBIRD_X_AUTH_TOKEN", "").strip()
    if environment_value:
        return environment_value, "environment"

    workspace = Path(__file__).resolve().parents[1]
    compatibility_source = (
        workspace
        / "FuckPrivateClient"
        / "fastlink"
        / "flyingbird-lite-3.0.3"
        / "downloader"
        / "main.go"
    )
    local_value = read_x_auth_from_go_source(compatibility_source)
    if local_value:
        return local_value, "existing-local-adapter"
    return None, None


def app_headers(
    user_agent: str,
    accept_language: str,
    authorization: str | None = None,
    x_auth_token: str | None = None,
) -> dict[str, str]:
    headers = common_headers(user_agent, accept_language, authorization)
    if x_auth_token:
        headers["x-auth-token"] = x_auth_token
        headers["x-app-package-name"] = "atlas"
        headers["x-client-platform"] = "all-platform"
    return headers


def resolve_credentials(args: argparse.Namespace) -> tuple[str, str]:
    email = (args.email or os.environ.get("FLYINGBIRD_EMAIL") or "").strip()
    if not email:
        email = input("FlyingBird email: ").strip()
    if not email:
        raise FetchError("Email is required.")

    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = os.environ.get("FLYINGBIRD_PASSWORD") or getpass.getpass("FlyingBird password: ")
    if not password:
        raise FetchError("Password is required.")
    return email, password


def export_decoded_subscription(
    args: argparse.Namespace,
    decoded: DecodedSubscription,
    payload: bytes,
    details: dict[str, Any],
) -> dict[str, Any]:
    output_dir = Path(args.output_dir).expanduser().resolve()
    suffix = ".yaml" if decoded.format == "mihomo-yaml" else ".txt"
    subscription_path = output_dir / f"flyingbird_subscription{suffix}"
    nodes_path = output_dir / "flyingbird_nodes.json"
    summary_path = output_dir / "flyingbird_summary.json"

    subscription_bytes = (decoded.text.rstrip() + "\n").encode("utf-8")
    nodes_document = {
        "format": decoded.format,
        "node_count": len(decoded.nodes),
        "nodes": decoded.nodes,
    }
    summary: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "ok",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "format": decoded.format,
        "decode_layers": decoded.decode_layers,
        "node_count": len(decoded.nodes),
        "node_types": decoded.node_types,
    }
    summary.update(details)
    summary["outputs"] = {
        "subscription": str(subscription_path),
        "nodes": str(nodes_path),
        "summary": str(summary_path),
    }

    atomic_write(subscription_path, subscription_bytes, sensitive=True)
    atomic_write(
        nodes_path,
        (json.dumps(nodes_document, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        sensitive=True,
    )
    atomic_write(
        summary_path,
        (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        sensitive=False,
    )
    return summary


def load_cached_nodes(args: argparse.Namespace) -> dict[str, Any]:
    cache_path = Path(args.cache_file).expanduser().resolve()
    if not cache_path.is_file():
        raise FetchError(f"FlyingBird app cache was not found: {cache_path}")
    desktop_prefs_path = Path(args.desktop_prefs_file).expanduser().resolve()
    desktop_subscribe_url = read_desktop_cached_subscription_url(desktop_prefs_path)
    link_details = verify_android_subscription_link(
        args,
        desktop_subscribe_url,
        "the desktop cached subscription link",
        desktop_prefs_path,
    )
    payload = cache_path.read_bytes()
    decoded = decode_subscription(payload)
    stat_result = cache_path.stat()
    details = {
        "source": "flyingbird-app-cache",
        "cache_file": str(cache_path),
        "cache_updated_utc": datetime.fromtimestamp(
            stat_result.st_mtime, timezone.utc
        ).isoformat(timespec="seconds"),
        "cache_bytes": stat_result.st_size,
    }
    details.update(link_details)
    return export_decoded_subscription(
        args,
        decoded,
        payload,
        details,
    )


def fetch_nodes(args: argparse.Namespace, email: str, password: str) -> dict[str, Any]:
    bases = [normalize_base_url(value) for value in (args.api_base_urls or DEFAULT_API_BASE_URLS)]
    session = requests.Session()
    session.headers["content-type"] = "application/json"
    attempts: list[dict[str, Any]] = []
    auth_token: str | None = None
    x_auth_token, x_auth_source = resolve_x_auth_token()
    subscribe_url: str | None = None
    resolved_base: str | None = None
    login_status: int | None = None
    info_status: int | None = None

    try:
        for base_url in bases:
            attempt: dict[str, Any] = {"api": safe_endpoint(base_url), "status": "started"}
            try:
                login_status, login_json = request_json(
                    session,
                    "POST",
                    api_url(base_url, LOGIN_PATH),
                    app_headers(
                        args.user_agent,
                        args.accept_language,
                        x_auth_token=x_auth_token,
                    ),
                    args.timeout,
                    {"email": email, "password": password},
                )
                auth_token = get_json_field(
                    login_json,
                    (
                        "data.auth_data",
                        "data.access_token",
                        "data.token",
                        "auth_data",
                        "access_token",
                        "token",
                    ),
                )
                if not auth_token:
                    raise FetchError("Login response did not contain an authorization token.")

                info_status, info_json = request_json(
                    session,
                    "GET",
                    api_url(base_url, SUBSCRIBE_INFO_PATH),
                    app_headers(
                        args.user_agent,
                        args.accept_language,
                        authorization=auth_token,
                        x_auth_token=x_auth_token,
                    ),
                    args.timeout,
                )
                subscribe_url = get_json_field(
                    info_json,
                    (
                        "data.subscribe_url",
                        "data.subscription_url",
                        "data.subscribeUrl",
                        "data.url",
                        "subscribe_url",
                        "subscription_url",
                        "subscribeUrl",
                        "url",
                    ),
                )
                if not subscribe_url:
                    match = re.search(
                        r"https://[A-Za-z0-9._:-]+/api/v1/client/subscribe\?token=[A-Za-z0-9_-]+",
                        json.dumps(info_json, ensure_ascii=False),
                        re.IGNORECASE,
                    )
                    subscribe_url = match.group(0) if match else None
                if not subscribe_url:
                    raise FetchError("Subscription response did not contain a subscription URL.")

                resolved_base = base_url
                attempt.update({"status": "ok", "login_http": login_status, "info_http": info_status})
                attempts.append(attempt)
                break
            except FetchError as exc:
                attempt.update(
                    {
                        "status": "error",
                        "error": sanitize_message(
                            str(exc),
                            (email, password, auth_token or "", x_auth_token or ""),
                        ),
                    }
                )
                attempts.append(attempt)
                auth_token = None
                subscribe_url = None

        if not resolved_base or not subscribe_url:
            details = "; ".join(
                f"{attempt['api']}: {attempt.get('error', attempt['status'])}" for attempt in attempts
            )
            raise FetchError(
                f"Login/subscription discovery failed for every configured API endpoint. {details}"
            )

        link_details = verify_android_subscription_link(
            args,
            subscribe_url,
            "the fresh API subscription link",
        )

        download_attempts: list[dict[str, Any]] = []
        response: requests.Response | None = None
        resolved_download_endpoint: str | None = None
        for candidate in subscribe_url_candidates(subscribe_url, resolved_base):
            endpoint = safe_endpoint(candidate)
            try:
                candidate_response = session.get(
                    candidate,
                    headers=app_headers(
                        args.user_agent,
                        args.accept_language,
                        x_auth_token=x_auth_token,
                    ),
                    timeout=args.timeout,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                download_attempts.append(
                    {"endpoint": endpoint, "status": "transport-error", "error_type": type(exc).__name__}
                )
                continue

            download_attempts.append(
                {
                    "endpoint": endpoint,
                    "status": "ok" if 200 <= candidate_response.status_code < 300 else "http-error",
                    "http": candidate_response.status_code,
                    "bytes": len(candidate_response.content),
                }
            )
            if 200 <= candidate_response.status_code < 300 and candidate_response.content:
                response = candidate_response
                resolved_download_endpoint = endpoint
                break

        if response is None or resolved_download_endpoint is None:
            raise FetchError("Subscription download failed for every derived endpoint.")

        decoded = decode_subscription(response.content)
        details = {
            "source": "fresh-api-login",
            "api_endpoint": safe_endpoint(resolved_base),
            "download_endpoint": resolved_download_endpoint,
            "login_http": login_status,
            "subscription_info_http": info_status,
            "download_http": response.status_code,
            "download_bytes": len(response.content),
            "x_auth_used": bool(x_auth_token),
            "x_auth_source": x_auth_source,
            "attempts": attempts,
            "download_attempts": download_attempts,
        }
        details.update(link_details)
        return export_decoded_subscription(
            args,
            decoded,
            response.content,
            details,
        )
    finally:
        auth_token = None
        x_auth_token = None
        subscribe_url = None
        session.close()


def build_parser() -> argparse.ArgumentParser:
    workspace = Path(__file__).resolve().parents[1]
    app_data = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    parser = argparse.ArgumentParser(
        description=(
            "Fetch FlyingBird nodes without persisting credentials or tokens. "
            "Every source is required to match the Android getSubscribe link exactly."
        )
    )
    parser.add_argument("--email", help="Account email; defaults to FLYINGBIRD_EMAIL or an interactive prompt.")
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read one password line from standard input. Passwords are intentionally not accepted as CLI arguments.",
    )
    parser.add_argument("--api-base-url", dest="api_base_urls", action="append", help="Override API base URL; repeat to add fallbacks.")
    parser.add_argument("--output-dir", default=str(workspace / "outputs" / "flyingbird_nodes"))
    parser.add_argument(
        "--cache-file",
        default=str(workspace / "portable_flyingbird_lite_new" / "latest.yaml"),
        help="FlyingBird-generated YAML cache used by --cache-only.",
    )
    parser.add_argument(
        "--cache-only",
        action="store_true",
        help="Skip API login and parse the app-generated cache after exact Android-link verification.",
    )
    parser.add_argument(
        "--android-getsubscribe-json",
        default=str(find_default_android_reference(workspace)),
        help="Android getSubscribe JSON used as the subscription-link source of truth (defaults to the newest local capture).",
    )
    parser.add_argument(
        "--desktop-prefs-file",
        default=str(app_data / "FlyingBird" / "FlyingBird" / "shared_preferences.json"),
        help="FlyingBird desktop shared_preferences.json used to verify --cache-only provenance.",
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--accept-language", default=DEFAULT_ACCEPT_LANGUAGE)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    email = ""
    password = ""
    try:
        if args.cache_only:
            summary = load_cached_nodes(args)
        else:
            email, password = resolve_credentials(args)
            summary = fetch_nodes(args, email, password)
        print("status=ok")
        print(f"source={summary['source']}")
        if summary.get("subscription_provenance"):
            print(f"subscription_provenance={summary['subscription_provenance']}")
        if "link_match" in summary:
            print(f"link_match={str(summary['link_match']).lower()}")
        if summary.get("api_endpoint"):
            print(f"api_endpoint={summary['api_endpoint']}")
        print(f"format={summary['format']}")
        print(f"node_count={summary['node_count']}")
        print(f"node_types={json.dumps(summary['node_types'], ensure_ascii=False, sort_keys=True)}")
        print(f"subscription={summary['outputs']['subscription']}")
        print(f"nodes={summary['outputs']['nodes']}")
        print(f"summary={summary['outputs']['summary']}")
        return 0
    except (FetchError, ValueError) as exc:
        print(f"status=error error={sanitize_message(str(exc), (email, password))}", file=sys.stderr)
        return 1
    finally:
        if password:
            password = "\0" * len(password)


if __name__ == "__main__":
    raise SystemExit(main())
