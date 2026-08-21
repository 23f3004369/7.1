#!/usr/bin/env python3
"""
CI/CD Container Release Gate Implementation
Deterministic policy endpoint for CI release metadata validation.
"""

from flask import Flask, request, jsonify
import re
import os
from urllib.parse import unquote, urlparse
# import html

app = Flask(__name__)

REQUIRED_PERMISSIONS = {
    'contents': 'read',
    'packages': 'write',
    'id-token': 'none'
}

ASSIGNED_TENANT = "tenant-lo8qnjv"
ALLOWED_EMAIL_DOMAIN = "notify-gazt8nx.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html"
}


# ============================================================
# QUESTION 1 - CI/CD RELEASE GATE
# ============================================================

def validate_permissions(permissions, violations):
    """Permissions must be exactly least privilege"""
    if permissions != REQUIRED_PERMISSIONS:
        violations.append('EXCESS_PERMISSION')


def validate_pr_trigger(event, trigger, violations):
    """PR must use pull_request, never pull_request_target"""
    if event == 'pull_request' and trigger == 'pull_request_target':
        violations.append('UNSAFE_PR_TRIGGER')


def validate_tests(workflow, violations):
    """Tests must pass, matrix must be complete, failFast must be false"""
    if (not workflow.get('testsPassed') or
        not workflow.get('matrixComplete') or
        workflow.get('failFast')):
        violations.append('TESTS_INCOMPLETE')


def validate_actions(actions, violations):
    """Third-party actions must be pinned to full 40-char SHA"""
    for action in actions:
        owner = action.get('owner', '')
        ref = action.get('ref', '')
        
        if owner == 'actions':
            continue  # GitHub official actions can use version tags
        
        if not isinstance(ref, str) or not re.match(r'^[a-f0-9]{40}$', ref):
            violations.append('MUTABLE_ACTION')


def validate_image(image, violations):
    """Image must be multi-stage, non-root, secure secret mode, no critical CVEs"""
    if not image.get('multiStage'):
        violations.append('SINGLE_STAGE_IMAGE')
    if image.get('runsAsRoot'):
        violations.append('ROOT_RUNTIME')
    if image.get('secretMode') not in ('none', 'buildkit'):
        violations.append('SECRET_IN_LAYER')
    if image.get('criticalVulnerabilities', 0) > 0:
        violations.append('CRITICAL_CVE')
    if not image.get('digestPinned'):
        violations.append('UNPINNED_IMAGE')


def validate_production(target, workflow, ref, violations):
    """Production requires push on main and environmentApproval"""
    if target != 'production':
        return
    
    if workflow.get('trigger') != 'push' or ref != 'refs/heads/main':
        violations.append('INVALID_PRODUCTION_REF')
    
    if not workflow.get('environmentApproval'):
        violations.append('APPROVAL_REQUIRED')


@app.route('/release-gate', methods=['POST'])
def release_gate():
    """
    Deterministic policy endpoint for CI release metadata.
    
    Returns JSON with decision and list of violation codes.
    """
    payload = request.get_json(force=True, silent=True) or {}
    
    violations = []
    
    workflow = payload.get('workflow', {})
    image = payload.get('image', {})
    
    # Apply all validation rules
    validate_permissions(workflow.get('permissions', {}), violations)
    validate_pr_trigger(
        payload.get('event'),
        workflow.get('trigger'),
        violations
    )
    validate_tests(workflow, violations)
    validate_actions(workflow.get('actions', []), violations)
    validate_image(image, violations)
    validate_production(
        payload.get('target'),
        workflow,
        payload.get('ref'),
        violations
    )
    
    return jsonify({
        'decision': 'promote' if not violations else 'block',
        'violations': violations
    })

# ============================================================
# QUESTION 2 - LLM ACTION FIREWALL
# ============================================================


ASSIGNED_TENANT = "tenant-lo8qnjv"
ALLOWED_EMAIL_DOMAIN = "notify-gazt8nx.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


def firewall_response(decision, reason):
    return jsonify({
        "decision": decision,
        "reason": reason,
    })


def valid_top_level(data):
    if not isinstance(data, dict):
        return False

    # These are the required top-level fields.
    required = {
        "provenance",
        "humanApproved",
        "action",
    }

    if not required.issubset(data.keys()):
        return False

    # untrustedContent is optional.
    if "untrustedContent" in data:
        if not isinstance(data["untrustedContent"], str):
            return False

    if data["provenance"] not in {"trusted", "untrusted"}:
        return False

    if not isinstance(data["humanApproved"], bool):
        return False

    action = data["action"]

    if not isinstance(action, dict):
        return False

    if set(action.keys()) != {"tool", "args"}:
        return False

    if not isinstance(action["tool"], str):
        return False

    if not isinstance(action["args"], dict):
        return False

    return True


def validate_tool_args(tool, args):

    if tool == "search":
        return (
            set(args.keys()) == {"query"}
            and isinstance(args["query"], str)
            and 1 <= len(args["query"]) <= 200
        )

    if tool == "lookup_record":
        return (
            set(args.keys()) == {"tenantId", "recordId"}
            and isinstance(args["tenantId"], str)
            and isinstance(args["recordId"], str)
            and len(args["tenantId"]) > 0
            and len(args["recordId"]) > 0
        )

    if tool == "send_email":
        return (
            set(args.keys()) == {"to", "subject", "body"}
            and isinstance(args["to"], str)
            and isinstance(args["subject"], str)
            and isinstance(args["body"], str)
            and len(args["to"]) > 0
        )

    if tool == "render_html":
        return (
            set(args.keys()) == {"html"}
            and isinstance(args["html"], str)
        )

    return False


def valid_email_domain(address):
    if not isinstance(address, str):
        return False

    # Exactly one @.
    if address.count("@") != 1:
        return False

    local, domain = address.rsplit("@", 1)

    if not local:
        return False

    # Exact domain match.
    return domain == ALLOWED_EMAIL_DOMAIN


def unsafe_html(html):
    """
    Deterministic HTML safety check.

    Reject:
    - script tags
    - iframe tags
    - inline event handlers
    - javascript: URLs
    """

    if re.search(r"<\s*script\b", html, re.IGNORECASE):
        return True

    if re.search(r"<\s*/\s*script\s*>", html, re.IGNORECASE):
        return True

    if re.search(r"<\s*iframe\b", html, re.IGNORECASE):
        return True

    # onclick=, onload=, onerror=, onmouseover=, etc.
    if re.search(r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=", html, re.IGNORECASE):
        return True

    if re.search(r"javascript\s*:", html, re.IGNORECASE):
        return True

    return False


@app.route("/action-firewall", methods=["POST"])
def action_firewall():

    # --------------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # --------------------------------------------------------

    try:
        data = request.get_json()
    except Exception:
        return firewall_response(
            "block",
            "INVALID_SCHEMA"
        )

    if not valid_top_level(data):
        return firewall_response(
            "block",
            "INVALID_SCHEMA"
        )

    action = data["action"]
    tool = action["tool"]
    args = action["args"]

    # --------------------------------------------------------
    # 2. TOOL ALLOWLIST
    # --------------------------------------------------------

    if tool not in ALLOWED_TOOLS:
        return firewall_response(
            "block",
            "TOOL_NOT_ALLOWED"
        )

    # --------------------------------------------------------
    # 3. SELECTED TOOL ARGUMENT SCHEMA
    # --------------------------------------------------------

    if not validate_tool_args(tool, args):
        return firewall_response(
            "block",
            "INVALID_SCHEMA"
        )

    # --------------------------------------------------------
    # 4. TENANT SCOPE
    # --------------------------------------------------------

    if tool == "lookup_record":

        if args["tenantId"] != ASSIGNED_TENANT:
            return firewall_response(
                "block",
                "TENANT_SCOPE"
            )

    # --------------------------------------------------------
    # 5. EMAIL EGRESS
    # --------------------------------------------------------

    if tool == "send_email":

        if not valid_email_domain(args["to"]):
            return firewall_response(
                "block",
                "EGRESS_DENIED"
            )

    # --------------------------------------------------------
    # 6. HUMAN APPROVAL
    # --------------------------------------------------------

    if tool == "send_email":

        if data["humanApproved"] is not True:
            return firewall_response(
                "block",
                "APPROVAL_REQUIRED"
            )

    # --------------------------------------------------------
    # 7. SAFE HTML OUTPUT
    # --------------------------------------------------------

    if tool == "render_html":

        if unsafe_html(args["html"]):
            return firewall_response(
                "block",
                "UNSAFE_OUTPUT"
            )

    # --------------------------------------------------------
    # EVERYTHING PASSED
    # --------------------------------------------------------

    return firewall_response(
        "allow",
        "ALLOW"
    )


# ============================================================
# HEALTH
# ============================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

# ============================================================
# QUESTION 3 - TERRAFORM PLAN POLICY GATE
# ============================================================

TERRAFORM_ENVIRONMENT = "prod-g24y5b"

REQUIRED_LABELS = {
    "owner": "student-0h0vk",
    "environment": "production",
    "cost_center": "cc-pcwi",
}

ALLOWED_STATE_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

PROTECTED_DELETE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


def terraform_response(decision, reason):
    return jsonify({
        "decision": decision,
        "reason": reason
    })


def valid_terraform_plan(data):
    if not isinstance(data, dict):
        return False

    required_top = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if set(data.keys()) != required_top:
        return False

    if not isinstance(data["environment"], str):
        return False

    if not isinstance(data["providerVersion"], str):
        return False

    if not isinstance(data["destroyApproved"], bool):
        return False

    # STATE
    state = data["state"]

    if not isinstance(state, dict):
        return False

    if set(state.keys()) != {"backend", "locked"}:
        return False

    if not isinstance(state["backend"], str):
        return False

    if not isinstance(state["locked"], bool):
        return False

    # RESOURCE
    resource = data["resource"]

    if not isinstance(resource, dict):
        return False

    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if set(resource.keys()) != required_resource:
        return False

    if not isinstance(resource["address"], str):
        return False

    if not isinstance(resource["type"], str):
        return False

    if resource["action"] not in {
        "create",
        "update",
        "delete",
    }:
        return False

    if not isinstance(resource["labels"], dict):
        return False

    if not isinstance(resource["forceDestroy"], bool):
        return False

    for key, value in resource["labels"].items():
        if not isinstance(key, str):
            return False
        if not isinstance(value, str):
            return False

    if resource["secret"] is not None:
        if not isinstance(resource["secret"], str):
            return False

    return True


def valid_provider_version(version):
    return version in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0"
    }


def valid_secret(secret):
    if secret is None:
        return True

    if not isinstance(secret, str):
        return False

    return secret.startswith("secret://") and len(secret) > len("secret://")


@app.route("/terraform/plan", methods=["POST"])
def terraform_plan():

    data = request.get_json(silent=True)

    # --------------------------------------------------------
    # 1. SCHEMA
    # --------------------------------------------------------

    if not valid_terraform_plan(data):
        return terraform_response(
            "reject",
            "INVALID_PLAN"
        )

    state = data["state"]
    resource = data["resource"]
    labels = resource["labels"]

    # --------------------------------------------------------
    # 2. ENVIRONMENT
    # --------------------------------------------------------

    if data["environment"] != TERRAFORM_ENVIRONMENT:
        return terraform_response(
            "reject",
            "ENVIRONMENT_MISMATCH"
        )

    # --------------------------------------------------------
    # 3. STATE
    # --------------------------------------------------------

    if (
        state["backend"] not in ALLOWED_STATE_BACKENDS
        or state["locked"] is not True
    ):
        return terraform_response(
            "reject",
            "STATE_UNSAFE"
        )

    # --------------------------------------------------------
    # 4. PROVIDER
    # --------------------------------------------------------

    if not valid_provider_version(
        data["providerVersion"]
    ):
        return terraform_response(
            "reject",
            "UNPINNED_PROVIDER"
        )

    # --------------------------------------------------------
    # 5. LABELS
    # --------------------------------------------------------

    for key, expected in REQUIRED_LABELS.items():
        if labels.get(key) != expected:
            return terraform_response(
                "reject",
                "MISSING_LABELS"
            )

    # --------------------------------------------------------
    # 6. SECRET
    # --------------------------------------------------------

    if not valid_secret(resource["secret"]):
        return terraform_response(
            "reject",
            "PLAINTEXT_SECRET"
        )

    # --------------------------------------------------------
    # 7. STATEFUL DELETE
    # --------------------------------------------------------

    if (
        resource["action"] == "delete"
        and resource["type"] in PROTECTED_DELETE_TYPES
        and data["destroyApproved"] is not True
    ):
        return terraform_response(
            "reject",
            "DELETE_NOT_APPROVED"
        )

    # --------------------------------------------------------
    # 8. PRODUCTION FORCE DESTROY
    # --------------------------------------------------------

    if (
        resource["type"] == "storage_bucket"
        and labels.get("environment") == "production"
        and resource["forceDestroy"] is True
    ):
        return terraform_response(
            "reject",
            "FORCE_DESTROY"
        )

    # --------------------------------------------------------
    # ALL RULES PASSED
    # --------------------------------------------------------

    return terraform_response(
        "approve",
        "APPROVE"
    )


# ============================================================
# QUESTION 4 - LLM OUTPUT HANDLING GATE
# ============================================================

ALLOWED_EXTERNAL_HOSTS = {
    "cdn-j3m8z42.example",
    "app-edid9pw.example",
}

VALID_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


def sanitize_response(safe, reason):
    return jsonify({
        "safe": safe,
        "reason": reason
    })


def valid_sanitize_schema(data):
    if not isinstance(data, dict):
        return False

    if "channel" not in data or "output" not in data:
        return False

    if data["channel"] not in VALID_CHANNELS:
        return False

    if not isinstance(data["output"], str):
        return False

    if len(data["output"]) > 20000:
        return False

    return True


def decode_once(value):
    """
    Decode exactly once, in this order:
      1. percent escapes
      2. HTML entities
      3. \\uXXXX escapes
    """

    # 1. Percent-decode once
    decoded = unquote(value)

    # 2. Decode ONLY the HTML entities specified by the question
    named_entities = {
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&amp;": "&",
    }

    for entity, replacement in named_entities.items():
        decoded = decoded.replace(entity, replacement)

    # Numeric decimal entities: &#NN;
    def decimal_entity(match):
        try:
            return chr(int(match.group(1), 10))
        except ValueError:
            return match.group(0)

    decoded = re.sub(
        r"&#([0-9]+);",
        decimal_entity,
        decoded
    )

    # Numeric hexadecimal entities: &#xNN;
    def hex_entity(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    decoded = re.sub(
        r"&#x([0-9a-fA-F]+);",
        hex_entity,
        decoded
    )

    # 3. Decode \uXXXX once
    def unicode_replace(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        unicode_replace,
        decoded
    )

    return decoded


def contains_dangerous_scheme(text):
    """
    Detect javascript:, data:, vbscript:
    with optional whitespace before the colon.
    """

    return bool(
        re.search(
            r"(?i)(?:javascript|data|vbscript)\s*:",
            text
        )
    )


def extract_urls(channel, text):
    urls = []

    if channel == "html":
        # Quoted src/href attributes
        pattern = (
            r"""(?i)\b(?:src|href)\s*=\s*"""
            r"""(["'])(.*?)\1"""
        )

        for match in re.finditer(pattern, text):
            urls.append(match.group(2))

    elif channel == "markdown":
        # URL inside ](...)
        pattern = r"""\]\(([^)]*)\)"""

        for match in re.finditer(pattern, text):
            target = match.group(1).strip()

            # Markdown may contain optional title after URL.
            # First whitespace-delimited token is the URL.
            if target:
                urls.append(target.split()[0])

    elif channel == "url":
        value = text.strip()

        if value:
            urls.append(value)

    return urls


def has_external_exfil(urls):
    """
    Absolute URLs must use exactly one of the allowed hosts.

    Relative URLs are allowed.
    Protocol-relative URLs count as absolute.
    """

    for value in urls:
        value = value.strip()

        if value.startswith("//"):
            parsed = urlparse("https:" + value)
        else:
            parsed = urlparse(value)

        # Relative reference
        if not parsed.scheme and not parsed.netloc:
            continue

        hostname = parsed.hostname

        if hostname is None:
            continue

        if hostname.lower() not in ALLOWED_EXTERNAL_HOSTS:
            return True

    return False


def has_dangerous_url(channel, text):
    """
    Returns True if text contains a dangerous scheme or
    an extracted URL has a non-http/https scheme.
    """

    if contains_dangerous_scheme(text):
        return True

    urls = extract_urls(channel, text)

    for value in urls:

        value = value.strip()

        if value.startswith("//"):
            # Protocol-relative references are resolved as HTTPS.
            continue

        parsed = urlparse(value)

        # If an extracted URL has a scheme, it must be http/https.
        if parsed.scheme:
            if parsed.scheme.lower() not in {"http", "https"}:
                return True

    return False


def has_script_tag(text):
    """
    Opening script, iframe, object or embed tag.
    """

    return bool(
        re.search(
            r"(?is)<\s*(?:script|iframe|object|embed)\b",
            text
        )
    )


def has_event_handler(text):
    """
    Detect on...= attributes.
    """

    return bool(
        re.search(
            r"""(?is)\bon[a-zA-Z0-9_-]+\s*=""",
            text
        )
    )


def has_sql_metachar(text):
    if re.search(r"['\"]", text):
        return True

    if ";" in text:
        return True

    if "--" in text:
        return True

    if "/*" in text:
        return True

    if re.search(r"(?i)\bunion\b", text):
        return True

    if re.search(r"(?i)\bor\s+1\s*=\s*1\b", text):
        return True

    return False


def has_shell_metachar(text):
    if re.search(r"[;&|`<>]", text):
        return True

    if "$(" in text:
        return True

    if "${" in text:
        return True

    return False


def would_trip_rule(channel, text):
    """
    Apply channel-specific rules in the exact order
    specified by the question.

    Used for the decoded-payload check.
    """

    if channel == "html":

        if has_script_tag(text):
            return True

        if has_event_handler(text):
            return True

        if has_dangerous_url(channel, text):
            return True

        if has_external_exfil(
            extract_urls(channel, text)
        ):
            return True

    elif channel == "markdown":

        if has_dangerous_url(channel, text):
            return True

        if has_external_exfil(
            extract_urls(channel, text)
        ):
            return True

    elif channel == "url":

        if has_dangerous_url(channel, text):
            return True

        if has_external_exfil(
            extract_urls(channel, text)
        ):
            return True

    elif channel == "sql":

        if has_sql_metachar(text):
            return True

    elif channel == "shell":

        if has_shell_metachar(text):
            return True

    return False


@app.route("/sanitize-output", methods=["POST"])
def sanitize_output():

    data = request.get_json(silent=True)

    # --------------------------------------------------------
    # 1. INVALID SCHEMA
    # --------------------------------------------------------

    if not valid_sanitize_schema(data):
        return sanitize_response(
            False,
            "INVALID_SCHEMA"
        )

    channel = data["channel"]
    output = data["output"]

    # --------------------------------------------------------
    # 2. ENCODED PAYLOAD
    # --------------------------------------------------------

    decoded = decode_once(output)

    if (
        decoded != output
        and would_trip_rule(channel, decoded)
    ):
        return sanitize_response(
            False,
            "ENCODED_PAYLOAD"
        )

    # --------------------------------------------------------
    # 3. CHANNEL RULES
    # --------------------------------------------------------

    if channel == "html":

        if has_script_tag(output):
            return sanitize_response(
                False,
                "SCRIPT_TAG"
            )

        if has_event_handler(output):
            return sanitize_response(
                False,
                "EVENT_HANDLER"
            )

        if has_dangerous_url(channel, output):
            return sanitize_response(
                False,
                "DANGEROUS_SCHEME"
            )

        if has_external_exfil(
            extract_urls(channel, output)
        ):
            return sanitize_response(
                False,
                "EXTERNAL_EXFIL"
            )

    elif channel == "markdown":

        if has_dangerous_url(channel, output):
            return sanitize_response(
                False,
                "DANGEROUS_SCHEME"
            )

        if has_external_exfil(
            extract_urls(channel, output)
        ):
            return sanitize_response(
                False,
                "EXTERNAL_EXFIL"
            )

    elif channel == "url":

        if has_dangerous_url(channel, output):
            return sanitize_response(
                False,
                "DANGEROUS_SCHEME"
            )

        if has_external_exfil(
            extract_urls(channel, output)
        ):
            return sanitize_response(
                False,
                "EXTERNAL_EXFIL"
            )

    elif channel == "sql":

        if has_sql_metachar(output):
            return sanitize_response(
                False,
                "SQL_METACHAR"
            )

    elif channel == "shell":

        if has_shell_metachar(output):
            return sanitize_response(
                False,
                "SHELL_METACHAR"
            )

    # --------------------------------------------------------
    # EVERYTHING PASSED
    # --------------------------------------------------------

    return sanitize_response(
        True,
        "SAFE"
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(
        host="0.0.0.0",
        port=port
    )
