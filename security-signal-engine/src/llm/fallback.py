"""
Fallback templates for when the LLM is unavailable.

Provides deterministic fix recommendations for common vulnerability
types as specified in PRD Table 9 (Section 5.6).

The fallback system now generates context-aware recommendations by
combining a base template with finding-specific details (file path,
description, code snippet, CWE). This ensures each finding gets a
unique, relevant explanation even without an LLM.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Base knowledge: per-vuln-type building blocks
# ---------------------------------------------------------------------------
# Each entry has:
#   base_explanation  – generic "what is this" (1-2 sentences)
#   fix_patterns      – dict of {CWE or context_keyword → specific fix}
#   default_fix       – used when no CWE/context match
#   impact_template   – sentence template with a {asset} placeholder

_VULN_KNOWLEDGE: dict[str, dict] = {
    "SQL_INJECTION": {
        "base_explanation": (
            "SQL Injection occurs when user-controlled input is directly "
            "interpolated into SQL queries, allowing an attacker to alter "
            "query logic."
        ),
        "fix_patterns": {
            "sqlite3": (
                "Replace string formatting (f-strings, %, .format()) with "
                "parameterized queries using placeholder syntax: "
                "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)). "
                "Never use f-strings inside execute()."
            ),
            "sqlalchemy": (
                "Use SQLAlchemy's built-in parameterized queries: "
                "session.query(User).filter(User.id == user_id). "
                "If using text(), pass parameters via bindparams: "
                "text('SELECT ... WHERE id = :uid').bindparams(uid=user_id)."
            ),
            "django": (
                "Use Django ORM queries instead of raw SQL: "
                "User.objects.filter(id=user_id). If raw SQL is required, "
                "pass parameters as a list: cursor.execute('...WHERE id=%s', [user_id])."
            ),
            "psycopg": (
                "Use psycopg2 parameterized queries: "
                "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)). "
                "Never use Python string formatting for SQL."
            ),
        },
        "default_fix": (
            "Use parameterized/prepared queries instead of string concatenation. "
            "Pass user input as bind parameters, not as part of the query string."
        ),
        "impact_template": (
            "An attacker could read, modify, or delete {asset}, potentially "
            "exfiltrating the entire database including credentials and PII."
        ),
        "default_asset": "database records",
    },
    "XSS": {
        "base_explanation": (
            "Cross-Site Scripting (XSS) allows attackers to inject malicious "
            "scripts into web pages viewed by other users."
        ),
        "fix_patterns": {
            "jinja2": (
                "Enable Jinja2 auto-escaping (autoescape=True) in your Environment. "
                "Avoid using |safe or Markup() on user-controlled content. "
                "Use {{ variable }} which auto-escapes by default."
            ),
            "render_template_string": (
                "Replace render_template_string() with render_template() using "
                "a .html file. Jinja2 auto-escapes in templates but NOT in "
                "render_template_string with manually built HTML strings."
            ),
            "flask": (
                "Use Jinja2 templates with auto-escaping (default in Flask). "
                "Never build HTML by string concatenation with user data. "
                "Use markupsafe.escape() for any manual HTML construction."
            ),
            "react": (
                "React auto-escapes JSX by default. Avoid dangerouslySetInnerHTML. "
                "If you must render HTML, sanitize it with DOMPurify first: "
                "DOMPurify.sanitize(userInput)."
            ),
            "django": (
                "Django templates auto-escape by default. Avoid using |safe "
                "or mark_safe() on user-controlled content."
            ),
        },
        "default_fix": (
            "Apply context-aware output encoding before rendering user content. "
            "Use your framework's built-in auto-escaping."
        ),
        "impact_template": (
            "An attacker could steal session tokens from {asset}, redirect "
            "users to phishing pages, or perform actions as the victim."
        ),
        "default_asset": "authenticated users",
    },
    "STORED_XSS": {
        "base_explanation": (
            "Stored XSS occurs when user input is saved to a database and later "
            "rendered in web pages without sanitization, affecting every visitor "
            "who views the stored content."
        ),
        "fix_patterns": {
            "flask": (
                "Sanitize user input before storing it in the database using "
                "bleach.clean() to strip dangerous tags. Also ensure output "
                "escaping via Jinja2 auto-escaping when rendering."
            ),
        },
        "default_fix": (
            "Sanitize user input before storage (strip script tags, event handlers). "
            "Apply output encoding when rendering stored content in HTML."
        ),
        "impact_template": (
            "Every user viewing the affected {asset} will have malicious code "
            "execute in their browser, enabling mass credential theft."
        ),
        "default_asset": "page",
    },
    "SSRF": {
        "base_explanation": (
            "Server-Side Request Forgery (SSRF) lets attackers make the server "
            "send HTTP requests to arbitrary URLs, including internal services."
        ),
        "fix_patterns": {
            "urllib": (
                "Replace urllib.request.urlopen() with a validated request: "
                "parse the URL, check the hostname is not in private IP ranges "
                "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254), "
                "and whitelist allowed domains."
            ),
            "requests": (
                "Before calling requests.get(url), validate the parsed hostname "
                "is not a private IP address and is in your allowed domain list. "
                "Use socket.getaddrinfo() to resolve DNS and check for private IPs."
            ),
            "httpx": (
                "Before calling httpx.get(url), validate the URL hostname against "
                "an allowlist. Resolve DNS with socket.getaddrinfo() to prevent "
                "DNS rebinding attacks targeting internal services."
            ),
        },
        "default_fix": (
            "Whitelist allowed domains for outbound requests. Block private IP "
            "ranges. Validate and resolve URLs before making requests."
        ),
        "impact_template": (
            "An attacker could access {asset} from within the server's network, "
            "potentially reading cloud metadata, internal APIs, or admin panels."
        ),
        "default_asset": "internal services",
    },
    "RCE": {
        "base_explanation": (
            "Remote Code Execution allows an attacker to execute arbitrary "
            "system commands on the server through user-controlled input."
        ),
        "fix_patterns": {
            "subprocess": (
                "Use subprocess.run() with shell=False and pass arguments as a list: "
                "subprocess.run(['cmd', arg1, arg2], shell=False). "
                "Never pass user input to shell=True or os.system()."
            ),
            "eval": (
                "Replace eval() with ast.literal_eval() for parsing data structures. "
                "For mathematical expressions, use a safe expression parser. "
                "Never eval() user-controlled strings."
            ),
            "exec": (
                "Remove exec() calls on user-controlled input. Use a sandboxed "
                "environment or whitelist of allowed operations instead."
            ),
        },
        "default_fix": (
            "Never pass user input to system command functions. Use subprocess "
            "with shell=False and argument lists. Replace eval/exec with safe alternatives."
        ),
        "impact_template": (
            "An attacker could take complete control of {asset}, access all data, "
            "install malware, and pivot to other infrastructure."
        ),
        "default_asset": "the server",
    },
    "HARDCODED_SECRET": {
        "base_explanation": (
            "Hardcoded credentials, API keys, or tokens in source code can be "
            "extracted by anyone with repository access."
        ),
        "fix_patterns": {
            ".env": (
                "Move the secret to a .env file and load it with python-dotenv: "
                "from dotenv import load_dotenv; load_dotenv(); "
                "secret = os.environ['SECRET_NAME']. Add .env to .gitignore."
            ),
            "aws": (
                "Use AWS IAM roles or AWS Secrets Manager instead of hardcoded "
                "AWS access keys. Remove the key from code and rotate it immediately."
            ),
            "password": (
                "Move the password to an environment variable. Use "
                "os.environ.get('DB_PASSWORD') instead of the literal string. "
                "Rotate the exposed password immediately."
            ),
        },
        "default_fix": (
            "Move secrets to environment variables or a secrets manager. "
            "Add secret files to .gitignore. Rotate any exposed credentials."
        ),
        "impact_template": (
            "The exposed credentials could grant unauthorized access to {asset}, "
            "enabling data theft or service abuse."
        ),
        "default_asset": "external services or databases",
    },
    "INSECURE_DESERIALIZATION": {
        "base_explanation": (
            "Insecure deserialization allows attackers to execute code or "
            "manipulate application logic by providing crafted serialized data."
        ),
        "fix_patterns": {
            "pickle": (
                "Replace pickle.loads() with json.loads() for data interchange. "
                "If pickle is required, validate data integrity with HMAC before "
                "deserialization and never unpickle untrusted input."
            ),
            "yaml": (
                "Replace yaml.load() with yaml.safe_load() which only allows "
                "basic Python types and prevents arbitrary code execution."
            ),
        },
        "default_fix": (
            "Use safe serialization formats (JSON). Replace pickle/yaml.load "
            "with safe alternatives. Validate data integrity before deserialization."
        ),
        "impact_template": (
            "An attacker could execute arbitrary code or bypass authentication "
            "by injecting crafted data into {asset}."
        ),
        "default_asset": "the deserialization endpoint",
    },
    "PATH_TRAVERSAL": {
        "base_explanation": (
            "Path traversal allows attackers to access files outside the "
            "intended directory by injecting '../' sequences into file paths."
        ),
        "fix_patterns": {
            "flask": (
                "Use flask.send_from_directory() with a fixed base directory. "
                "Validate the resolved path with os.path.realpath() and confirm "
                "it starts with the allowed base path."
            ),
            "open": (
                "Canonicalize the path with os.path.realpath(os.path.join(base, user_input)) "
                "and verify the result starts with the expected base directory. "
                "Reject any path containing '..'."
            ),
        },
        "default_fix": (
            "Canonicalize file paths with os.path.realpath(). Verify the resolved "
            "path is within the allowed directory. Reject paths with '..' segments."
        ),
        "impact_template": (
            "An attacker could read sensitive files from {asset} such as "
            "/etc/passwd, .env files, or application source code."
        ),
        "default_asset": "the server filesystem",
    },
    "MISSING_AUTH": {
        "base_explanation": (
            "This endpoint or function lacks authentication, allowing "
            "unauthenticated users to access protected resources."
        ),
        "fix_patterns": {
            "flask": (
                "Add @login_required decorator from Flask-Login to protect the "
                "route. Ensure flask_login.current_user.is_authenticated is "
                "checked before serving sensitive data."
            ),
            "django": (
                "Add @login_required decorator from django.contrib.auth.decorators "
                "to the view. For class-based views, use LoginRequiredMixin."
            ),
            "fastapi": (
                "Add a Depends(get_current_user) parameter to the endpoint. "
                "Implement OAuth2PasswordBearer or API key authentication."
            ),
        },
        "default_fix": (
            "Add authentication middleware or decorators to all sensitive endpoints. "
            "Verify user identity before serving protected data."
        ),
        "impact_template": (
            "Unauthenticated users could access {asset}, potentially viewing "
            "or modifying sensitive data without authorization."
        ),
        "default_asset": "protected resources",
    },
    "IDOR": {
        "base_explanation": (
            "Insecure Direct Object Reference (IDOR) allows users to access "
            "other users' data by changing predictable resource identifiers."
        ),
        "fix_patterns": {},
        "default_fix": (
            "Add authorization checks that verify the requesting user owns or "
            "has permission to access the requested resource. Use UUIDs instead "
            "of sequential integer IDs to make enumeration harder."
        ),
        "impact_template": (
            "An attacker could access or modify other users' {asset} by "
            "incrementing or guessing resource identifiers."
        ),
        "default_asset": "profiles and personal data",
    },
    "OPEN_REDIRECT": {
        "base_explanation": (
            "Open redirect allows attackers to redirect users from your "
            "trusted domain to a malicious site via a URL parameter."
        ),
        "fix_patterns": {
            "flask": (
                "Validate the redirect target with urllib.parse.urlparse(). "
                "Ensure the netloc is empty (relative path) or matches your domain. "
                "Use flask.url_for() for internal redirects instead of raw URLs."
            ),
            "django": (
                "Use django.utils.http.url_has_allowed_host_and_scheme() to "
                "validate redirect URLs. Set allowed_hosts to your domain."
            ),
        },
        "default_fix": (
            "Validate redirect URLs against a whitelist of allowed domains. "
            "Use relative paths for internal redirects. Reject external URLs."
        ),
        "impact_template": (
            "Attackers could send users convincing phishing links via {asset} "
            "that appear to originate from your trusted domain."
        ),
        "default_asset": "your application's redirect endpoint",
    },
    "INSECURE_CRYPTO": {
        "base_explanation": (
            "The application uses weak or deprecated cryptographic algorithms "
            "that can be broken by modern attackers."
        ),
        "fix_patterns": {
            "md5": (
                "Replace MD5 with SHA-256 or SHA-3 for hashing: "
                "hashlib.sha256(data).hexdigest(). For password hashing, "
                "use bcrypt or argon2."
            ),
            "sha1": (
                "Replace SHA-1 with SHA-256: hashlib.sha256(data).hexdigest(). "
                "SHA-1 has known collision attacks."
            ),
            "des": (
                "Replace DES/3DES with AES-256-GCM. Use the cryptography library: "
                "from cryptography.hazmat.primitives.ciphers.aead import AESGCM."
            ),
        },
        "default_fix": (
            "Use AES-256 for encryption, SHA-256+ for hashing, bcrypt/argon2 "
            "for passwords, and Ed25519 for signing. Avoid MD5, SHA-1, DES, RC4."
        ),
        "impact_template": (
            "Encrypted {asset} could be decrypted by attackers using known "
            "weaknesses in the deprecated algorithm."
        ),
        "default_asset": "sensitive data",
    },
    # ── URL Scanner vulnerability types ──────────────────────
    "MISSING_SECURITY_HEADER": {
        "base_explanation": (
            "The server response is missing recommended HTTP security headers "
            "that instruct browsers to enable built-in protections."
        ),
        "fix_patterns": {
            "X-Frame-Options": (
                "Add the X-Frame-Options header set to 'DENY' or 'SAMEORIGIN' "
                "to prevent clickjacking. In Flask: "
                "response.headers['X-Frame-Options'] = 'DENY'."
            ),
            "Content-Security-Policy": (
                "Add a Content-Security-Policy header to restrict script sources: "
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'."
            ),
            "X-Content-Type-Options": (
                "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing "
                "attacks that could execute uploaded files as scripts."
            ),
            "Strict-Transport-Security": (
                "Add Strict-Transport-Security: max-age=31536000; includeSubDomains "
                "to force HTTPS connections and prevent SSL stripping."
            ),
            "Referrer-Policy": (
                "Add Referrer-Policy: strict-origin-when-cross-origin to control "
                "what URL information is sent in the Referer header."
            ),
        },
        "default_fix": (
            "Configure your web server to send security headers: "
            "Strict-Transport-Security, Content-Security-Policy, "
            "X-Content-Type-Options, X-Frame-Options, Referrer-Policy."
        ),
        "impact_template": (
            "Without this header, {asset} is more vulnerable to "
            "XSS, clickjacking, or MIME-type confusion attacks."
        ),
        "default_asset": "users' browsers",
    },
    "CLICKJACKING": {
        "base_explanation": (
            "The page can be embedded in an iframe, allowing attackers "
            "to overlay invisible controls and trick users into clicking."
        ),
        "fix_patterns": {},
        "default_fix": (
            "Add X-Frame-Options: DENY header or use Content-Security-Policy "
            "with frame-ancestors 'self'."
        ),
        "impact_template": (
            "Users could be tricked into performing unintended actions on {asset} "
            "such as changing settings or transferring funds."
        ),
        "default_asset": "your application",
    },
    "INFORMATION_DISCLOSURE": {
        "base_explanation": (
            "The server is exposing sensitive information that could help "
            "attackers plan targeted attacks."
        ),
        "fix_patterns": {
            ".env": (
                "Block access to .env files in your web server config. "
                "In nginx: location ~ /\\.env { deny all; }. "
                "In Apache: <FilesMatch \"^\\.env\"> Require all denied </FilesMatch>."
            ),
            ".git": (
                "Block access to .git/ directory in your web server config. "
                "In nginx: location ~ /\\.git { deny all; }. "
                "Remove the .git directory from the deployed artifact."
            ),
            "backup": (
                "Remove database backup files from the web root. Store backups "
                "in a non-web-accessible directory. Add rules to deny access to "
                "*.sql, *.bak, *.dump file extensions."
            ),
            "Server": (
                "Suppress the Server header version information. "
                "In nginx: server_tokens off; "
                "In Apache: ServerTokens Prod. "
                "In Flask: remove or override the Server header."
            ),
            "X-Powered-By": (
                "Remove the X-Powered-By header from responses. "
                "In Express: app.disable('x-powered-by'). "
                "In Flask: del response.headers['X-Powered-By']."
            ),
            "stack trace": (
                "Disable debug mode in production. Never display stack traces "
                "to end users. Log errors server-side and return generic error pages."
            ),
            "API": (
                "Rotate the exposed API key immediately. Move API keys to "
                "environment variables. Remove any hardcoded keys from HTML comments."
            ),
            "robots.txt": (
                "Review robots.txt for sensitive path disclosure. While robots.txt "
                "is public, listing hidden paths like /admin or /backup reveals "
                "targets to attackers. Use authentication instead of obscurity."
            ),
        },
        "default_fix": (
            "Remove or restrict access to the exposed sensitive information. "
            "Suppress version headers, block sensitive file access, and "
            "disable debug output in production."
        ),
        "impact_template": (
            "The disclosed {asset} helps attackers identify attack vectors, "
            "reducing the effort needed for a successful breach."
        ),
        "default_asset": "server configuration details",
    },
    "INSECURE_TRANSPORT": {
        "base_explanation": (
            "The site is served over unencrypted HTTP, exposing all traffic "
            "to interception."
        ),
        "fix_patterns": {},
        "default_fix": (
            "Enable HTTPS with a valid TLS certificate (e.g. via Let's Encrypt). "
            "Redirect all HTTP traffic to HTTPS. Add the HSTS header."
        ),
        "impact_template": (
            "All data transmitted to {asset} — including passwords and session "
            "tokens — can be intercepted on the network."
        ),
        "default_asset": "this site",
    },
    "INSECURE_COOKIE": {
        "base_explanation": (
            "One or more cookies are missing important security flags, making "
            "them vulnerable to theft or misuse."
        ),
        "fix_patterns": {
            "session": (
                "Set Secure, HttpOnly, and SameSite=Lax on the session cookie. "
                "In Flask: app.config['SESSION_COOKIE_SECURE'] = True; "
                "app.config['SESSION_COOKIE_HTTPONLY'] = True; "
                "app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'."
            ),
            "token": (
                "Set HttpOnly on authentication token cookies to prevent "
                "JavaScript access via XSS. Add Secure flag for HTTPS-only "
                "transmission."
            ),
        },
        "default_fix": (
            "Set Secure, HttpOnly, and SameSite flags on all sensitive cookies."
        ),
        "impact_template": (
            "The {asset} cookie could be stolen via XSS or transmitted over "
            "insecure connections, enabling session hijacking."
        ),
        "default_asset": "session",
    },
    "CORS_MISCONFIGURATION": {
        "base_explanation": (
            "The CORS policy is overly permissive, allowing unauthorized "
            "websites to make authenticated requests on behalf of users."
        ),
        "fix_patterns": {
            "wildcard": (
                "Replace Access-Control-Allow-Origin: * with specific trusted "
                "domains. Never use wildcard with Allow-Credentials: true."
            ),
            "reflect": (
                "Stop reflecting the Origin header as Allow-Origin. Maintain "
                "a whitelist of allowed origins and validate against it."
            ),
        },
        "default_fix": (
            "Restrict Access-Control-Allow-Origin to specific trusted domains. "
            "Never combine wildcard origins with Allow-Credentials: true."
        ),
        "impact_template": (
            "A malicious website could read {asset} on behalf of authenticated "
            "users, potentially accessing sensitive data."
        ),
        "default_asset": "API responses",
    },
    "XXE": {
        "base_explanation": (
            "XML External Entity (XXE) injection allows attackers to read "
            "server files, make outbound requests, or cause denial of service "
            "through crafted XML input."
        ),
        "fix_patterns": {
            "etree": (
                "Disable external entity processing in ElementTree: use "
                "defusedxml.ElementTree instead of xml.etree.ElementTree. "
                "Install with: pip install defusedxml."
            ),
            "lxml": (
                "Disable external entities in lxml: parser = etree.XMLParser("
                "resolve_entities=False, no_network=True). "
                "Alternatively use defusedxml.lxml."
            ),
        },
        "default_fix": (
            "Use defusedxml instead of the standard xml library. "
            "Disable external entity resolution and DTD processing."
        ),
        "impact_template": (
            "An attacker could read files from {asset}, make outbound requests "
            "to internal services, or cause denial of service."
        ),
        "default_asset": "the server",
    },
    "DIRECTORY_LISTING": {
        "base_explanation": (
            "Directory listing is enabled, exposing the file structure and "
            "contents of server directories to anyone."
        ),
        "fix_patterns": {},
        "default_fix": (
            "Disable directory listing in your web server. "
            "In nginx: autoindex off; In Apache: Options -Indexes."
        ),
        "impact_template": (
            "Attackers can browse {asset} to discover sensitive files, "
            "backup archives, configuration files, and source code."
        ),
        "default_asset": "server directories",
    },
    "DANGEROUS_HTTP_METHOD": {
        "base_explanation": (
            "The server accepts dangerous HTTP methods (PUT, DELETE, TRACE) "
            "that could be exploited to modify or delete resources."
        ),
        "fix_patterns": {},
        "default_fix": (
            "Restrict allowed HTTP methods to GET, POST, and OPTIONS in your "
            "web server or application configuration. Disable TRACE and TRACK."
        ),
        "impact_template": (
            "Attackers could use dangerous methods to modify or delete {asset}, "
            "or use TRACE for cross-site tracing attacks."
        ),
        "default_asset": "server resources",
    },
}

# Generic fallback for unknown vulnerability types
_DEFAULT_KNOWLEDGE = {
    "base_explanation": (
        "A security vulnerability was detected in your code."
    ),
    "fix_patterns": {},
    "default_fix": (
        "Review the flagged code and apply security best practices. "
        "Consult the OWASP guidelines for the relevant vulnerability type."
    ),
    "impact_template": (
        "This vulnerability could be exploited to compromise {asset}."
    ),
    "default_asset": "application security",
}


# ---------------------------------------------------------------------------
# Context-aware fallback analysis
# ---------------------------------------------------------------------------

def get_fallback_analysis(
    vuln_type: str,
    *,
    description: str = "",
    code_snippet: str = "",
    file_path: str = "",
    cwe_id: str = "",
) -> dict[str, str]:
    """
    Generate a context-aware fallback analysis for a vulnerability finding.

    Unlike a flat dictionary lookup, this function inspects the actual
    finding data (description, code snippet, file path, CWE) to select
    the most specific fix recommendation from the knowledge base.

    Returns a dict with 'explanation', 'fix_suggestion', and 'business_impact'.
    """
    knowledge = _VULN_KNOWLEDGE.get(vuln_type, _DEFAULT_KNOWLEDGE)

    # -- Build context string from all available finding data
    context = f"{description} {code_snippet} {file_path} {cwe_id}".lower()

    # -- Select the most specific explanation
    explanation = knowledge["base_explanation"]
    if description:
        # Append finding-specific details to make each explanation unique
        explanation = f"{explanation} {_summarize_context(description, file_path)}"

    # -- Select the best fix recommendation by matching context keywords
    fix = _select_best_fix(knowledge, context)

    # -- Build a context-aware impact statement
    asset = _detect_asset(context, knowledge.get("default_asset", "the application"))
    impact = knowledge.get("impact_template", "This could compromise {asset}.").format(
        asset=asset
    )

    return {
        "explanation": explanation,
        "fix_suggestion": fix,
        "business_impact": impact,
    }


def _summarize_context(description: str, file_path: str) -> str:
    """Create a brief context sentence from the finding's own data."""
    parts = []
    if file_path:
        filename = file_path.replace("\\", "/").split("/")[-1]
        parts.append(f"Found in {filename}")
    if description and len(description) > 20:
        # Use the first meaningful sentence from the description
        first_sentence = description.split(".")[0].strip()
        if first_sentence and first_sentence != description:
            parts.append(first_sentence)
    return ". ".join(parts) + "." if parts else ""


def _select_best_fix(knowledge: dict, context: str) -> str:
    """
    Select the most specific fix by matching context keywords against
    the knowledge base's fix_patterns dictionary.
    """
    fix_patterns = knowledge.get("fix_patterns", {})
    best_match = None
    best_score = 0

    for keyword, fix_text in fix_patterns.items():
        keyword_lower = keyword.lower()
        # Score based on how many times the keyword appears and its length
        occurrences = context.count(keyword_lower)
        if occurrences > 0:
            score = occurrences * len(keyword_lower)
            if score > best_score:
                best_score = score
                best_match = fix_text

    return best_match or knowledge.get("default_fix", "")


def _detect_asset(context: str, default_asset: str) -> str:
    """
    Detect what specific asset is at risk based on context keywords.
    This makes the impact statement unique per finding.
    """
    asset_keywords = {
        "password": "user credentials and passwords",
        "session": "user session data",
        "cookie": "session cookies",
        "token": "authentication tokens",
        "api_key": "API keys",
        "api key": "API keys",
        "database": "the database",
        "backup": "database backup files",
        ".env": "environment variables and secrets",
        ".git": "Git repository metadata and history",
        "admin": "the admin panel",
        "user": "user accounts and personal data",
        "payment": "payment and financial data",
        "credit": "credit card information",
        "health": "health records (HIPAA data)",
        "email": "email addresses",
        "customer": "customer records",
        "internal": "internal network services",
        "metadata": "cloud instance metadata",
        "config": "configuration files",
        "robots.txt": "site structure (via robots.txt disclosure)",
        "x-powered-by": "server technology stack (via X-Powered-By header)",
        "server:": "server software version (via Server header)",
    }

    for keyword, asset_name in asset_keywords.items():
        if keyword in context:
            return asset_name

    return default_asset


# ---------------------------------------------------------------------------
# Executive summary (unchanged)
# ---------------------------------------------------------------------------

def generate_fallback_executive_summary(
    total_raw: int,
    after_dedup: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    target: str,
) -> str:
    """Generate a rule-based executive summary when LLM is unavailable."""
    parts = [
        f"Security scan of '{target}' identified {total_raw} raw findings, "
        f"reduced to {after_dedup} unique issues after deduplication."
    ]

    if critical > 0:
        parts.append(
            f"⚠️ {critical} CRITICAL issue(s) require immediate attention "
            f"and should be fixed before the next deployment."
        )
    if high > 0:
        parts.append(
            f"🟠 {high} HIGH-severity issue(s) should be prioritized "
            f"for remediation within the next 48 hours."
        )
    if medium > 0:
        parts.append(
            f"{medium} MEDIUM-priority issue(s) should be addressed "
            f"in the current development sprint."
        )
    if low > 0:
        parts.append(
            f"{low} LOW-priority issue(s) have been logged for backlog tracking."
        )
    if critical == 0 and high == 0 and medium == 0 and low == 0:
        parts.append(
            "No significant security issues were found. "
            "Continue following security best practices."
        )

    return " ".join(parts)
