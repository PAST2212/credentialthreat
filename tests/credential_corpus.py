"""Hand-labeled, inert HTML responses. Scenario labels never enter the HTML."""

from dataclasses import dataclass


RULES = ("assignment", "jwt", "private_key", "aws_keys")


@dataclass(frozen=True)
class Target:
    text: str
    rules: tuple[str, ...]
    example: bool = False  # intentionally published by the fictional owner


@dataclass(frozen=True)
class Page:
    name: str
    html: str
    # Exact half-open offsets in the raw response, assigned while composing the page.
    annotations: tuple[tuple[int, int, Target], ...]


def page(name, *parts):
    html = "<!doctype html><html><body>"
    annotations = []
    for part in parts:
        if isinstance(part, Target):
            start = len(html)
            html += part.text
            annotations.append((start, len(html), part))
        else:
            html += part
    return Page(name, html + "</body></html>", tuple(annotations))


A = ("assignment",)
J = ("jwt",)
P = ("private_key",)
K = ("aws_keys",)

VALUE = "FIXTUREONLY123"
# Deliberately inert shapes. The PEM body decodes to plain text, the JWT
# header specifies a fictional algorithm, and the ID has no associated key.
JWT = "eyJhbGciOiJGSVhUVVJFIn0.eyJ0ZXN0Ijp0cnVlfQ.RklYVFVSRQ"
PEM = "-----BEGIN PRIVATE KEY-----\nRklYVFVSRQ==\n-----END PRIVATE KEY-----"
RSA = PEM.replace("PRIVATE KEY", "RSA PRIVATE KEY")
ID = "AKIA" + "TEST" * 4

PAGES = (
    page("inline-config", '<script>api_key = "', Target(VALUE, A), '";</script>'),
    page("quoted-config", "<script>client_secret = '", Target("FIXTURETWO", A), "';</script>"),
    page("line-break", '<script>auth_token =\n "', Target(VALUE, A), '";</script>'),
    page("json-config", '<script type="application/json">{"api_key":"', Target(VALUE, A), '"}</script>'),
    page("alias-private", '<script>private_key = "', Target(VALUE, A), '";</script>'),
    page("assignment-guide", '<script>api_key = "', Target(VALUE, A, example=True), '";</script>'),
    page("public-key-help", '<pre>public_key = "', Target("PUBLICFIXTURE", A, example=True), '"</pre>'),
    page("debug-option", '<script>app_debug = "DISABLED";</script>'),
    page("log-option", '<script>app_log_level = "CRITICAL";</script>'),
    page("unequal-quotes", """<script>api_key = "FIXTUREONLY123';</script>"""),
    page("next-property", '<script>x={withCredentials:this.withCredentials,requestType:"arraybuffer"}</script>'),
    page("two-assignments", '<script>api_key="', Target(VALUE, A), '"; api_key="', Target(VALUE, A), '";</script>'),
    page("mixed-config", '<pre>api_key="', Target(VALUE, A, example=True),
         '"</pre><script type="application/json">{"client_secret":"', Target(VALUE, A), '"}</script>'),
    page("jwt-script", '<script>const fixture = "', Target(JWT, J), '";</script>'),
    page("jwt-attribute", '<div data-value="', Target(JWT, J), '"></div>'),
    page("jwt-list", '<ul><li>', Target(JWT, J), '</li><li>', Target(JWT, J), '</li></ul>'),
    page("jwt-manual", '<script>const fixture = "', Target(JWT, J, example=True), '";</script>'),
    page("jwt-empty", '<p>JWT example omitted</p>'),
    page("jwt-header-only", '<code>eyJhbGciOiJGSVhUVVJFIn0</code>'),
    page("pem-panel", '<pre>', Target(PEM, P), '</pre>'),
    page("pem-rsa", '<textarea>', Target(RSA, P), '</textarea>'),
    page("pem-pair", '<pre>', Target(PEM, P), '\n', Target(RSA, P), '</pre>'),
    page("pem-manual", '<pre>', Target(PEM, P, example=True), '</pre>'),
    page("pem-crlf", '<pre>', Target(PEM.replace('\n', '\r\n'), P), '</pre>'),
    page("pem-crossed-a", '<pre>', RSA.replace("END RSA PRIVATE", "END PRIVATE"), '</pre>'),
    page("pem-crossed-b", '<pre>', PEM.replace("END PRIVATE", "END RSA PRIVATE"), '</pre>'),
    page("pem-unclosed", '<pre>-----BEGIN PRIVATE KEY-----\nRklYVFVSRQ==</pre>'),
    page("id-panel", '<span>', Target(ID, K), '</span>'),
    page("id-attribute", '<div data-id="', Target(ID, K), '"></div>'),
    page("id-list", '<ul><li>', Target(ID, K), '</li><li>', Target(ID, K), '</li></ul>'),
    page("id-manual", '<span>', Target(ID, K, example=True), '</span>'),
    page("id-empty", '<p>identifier withheld</p>'),
    page("id-truncated", '<code>', ID[:9], '</code>'),
    page("same-position", '<script>api_key="', Target(ID, ("assignment", "aws_keys")), '";</script>'),
    page("empty-page", ""),
    page("ordinary-text", "<p>Account settings are available in the menu.</p>"),
    page("mixed-script", '<script>app_debug="DISABLED"; api_key="', Target(VALUE, A),
         '"; const note="', Target(JWT, J, example=True), '";</script>'),
)
