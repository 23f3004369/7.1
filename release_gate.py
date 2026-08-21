#!/usr/bin/env python3
"""
CI/CD Container Release Gate Implementation
Deterministic policy endpoint for CI release metadata validation.
"""

from flask import Flask, request, jsonify
import re
import os

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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(
        host="0.0.0.0",
        port=port
    )
