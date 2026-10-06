"""Authorisation adapters: how the harness gets past consumer authentication and consent.

The CTS authorises as a test consumer at the DH. Every DH does that
differently, so the step is pluggable. An adapter is a callable::

    adapter(client, request, authorization_url, options) -> callback_url

It must return the URL the DH redirected the browser to — the simulated ADR's
redirect URI carrying the JARM ``response`` — and is selected with
``authorization.adapter: "module:function"`` in the configuration.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from .errors import AuthorizationError, CtsError
from .fapi import AuthorizationRequest, FapiClient

Adapter = Callable[[FapiClient, AuthorizationRequest, str, Mapping[str, Any]], str]


def load_callable(spec: str) -> Callable[..., Any]:
    module_name, _, attribute = spec.partition(":")
    if not module_name or not attribute:
        raise CtsError(f"expected 'module:function', got {spec!r}")
    try:
        return getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError) as exc:
        raise CtsError(f"cannot load {spec!r}: {exc}") from exc


def direct_redirect(
    client: FapiClient, request: AuthorizationRequest, authorization_url: str, options: Mapping[str, Any]
) -> str:
    """Follow the DH's redirects until one lands on the redirect URI.

    Works where the DH's test authentication completes without interaction
    (an auto-login adapter or a pre-authenticated test identity). Options:
    ``max_hops`` (default 10).
    """
    redirect_uri = client.config.redirect_uri
    url = authorization_url
    for _ in range(int(options.get("max_hops", 10))):
        if url.startswith(redirect_uri):
            return url
        response = client.http.get(url)
        location = response.headers.get("location")
        if response.status_code not in (301, 302, 303, 307, 308) or not location:
            raise CtsError(
                f"authorisation stopped at HTTP {response.status_code} ({url.split('?')[0]}) without reaching the "
                "redirect URI; this DH needs an interactive adapter (see authorization.adapter)"
            )
        url = urljoin(url, location)
    if url.startswith(redirect_uri):
        return url
    raise CtsError("too many redirects during authorisation")


def ecosystem_callback(
    client: FapiClient, request: AuthorizationRequest, authorization_url: str, options: Mapping[str, Any]
) -> str:
    """Hand the authorisation URL to an operator and wait for the redirect at the mock ADR.

    The operator (or a browser-automation tool) opens the URL, authenticates as
    the test consumer and approves the consent; the DH redirects to the mock's
    ``/dr/signin``, which records it. Options: ``timeout`` (seconds).
    """
    from .ecosystem import Ecosystem  # local import: only this adapter needs the admin API

    timeout = float(options.get("timeout", client.config.timeouts.authorization))
    print(f"\n  >> Open this URL, sign in as the test consumer and approve the consent:\n     {authorization_url}\n")
    ecosystem = Ecosystem(client.config.ecosystem.admin_url, timeout=client.config.timeouts.http)
    try:
        found = ecosystem.wait_for(lambda: ecosystem.callbacks(request.state), timeout)
    finally:
        ecosystem.close()
    if not found:
        raise CtsError(f"no redirect for state {request.state} reached the mock ADR within {timeout:.0f}s")
    params = {k: v for k, v in found[-1]["params"].items() if v is not None}
    return f"{client.config.redirect_uri}?{urlencode(params)}"


def jarm_from_callback(callback_url: str) -> str:
    """Extract the JARM ``response`` from a redirect URL (query or fragment)."""
    parsed = urlparse(callback_url)
    params = parse_qs(parsed.query) or parse_qs(parsed.fragment)
    if "response" in params:
        return params["response"][0]
    if "error" in params:
        raise AuthorizationError(params["error"][0], params.get("error_description", [""])[0])
    raise CtsError("the redirect carries neither a JARM 'response' nor an 'error'")
