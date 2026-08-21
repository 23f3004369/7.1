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


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)

