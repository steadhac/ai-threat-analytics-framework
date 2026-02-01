"""Shared Allure reporting helpers for all test suites."""

import allure


def attach_mitigation(playbook_num, name, description, implementation, mitigates, coverage):
    """Helper to attach mitigation details to Allure report.
    
    Used by: All test files
    Purpose: Standardized OWASP threat mitigation documentation
    
    Args:
        playbook_num: Mitigation playbook number (1-6)
        name: Mitigation name
        description: What this mitigation does
        implementation: How it's implemented in tests
        mitigates: OWASP threats addressed
        coverage: What assertions cover this mitigation
    """
    mitigation_details = f"""
MITIGATION {playbook_num}: {name}

Description: {description}
Implementation: {implementation}
Mitigates: {mitigates}
Test Coverage: {coverage}
"""
    allure.attach(mitigation_details, 
                 name=f"Mitigation {playbook_num}: {name}", 
                 attachment_type=allure.attachment_type.TEXT)


def attach_stage_details(stage_name, details):
    """Helper to attach stage/step explanations to Allure report.
    
    Used by: All test files
    Purpose: Document pipeline stages, test phases, or detailed steps
    
    Args:
        stage_name: Name of the stage or step
        details: Description of what happens in this stage
    """
    allure.attach(details, 
                 name=f"{stage_name} Details", 
                 attachment_type=allure.attachment_type.TEXT)

def attach_vulnerabilities_mitigated():
    """Helper to attach complete vulnerabilities mitigated reference to report.
    
    Used by: Test suite initialization
    Purpose: Document all OWASP Agentic AI threats addressed by test suite
    Displays: Vulnerabilities Mitigated section in Allure report
    """
    vulnerabilities_reference = """
OWASP AGENTIC AI THREATS MITIGATED

T2 (Tool Misuse)
    Risk: Malformed data could cause tools to execute incorrectly or access unauthorized resources
    Mitigation: Dual-field validation (status + value) ensures tools receive correct data format
    Implementation: Filter invalid records before processing prevents tool confusion

T4 (Resource Overload)
    Risk: Processing null values can cause memory leaks and resource starvation
    Mitigation: Early filtering removes problematic records before they consume resources
    Implementation: Detect and remove null/malformed records at validation stage

T5 (Cascading Hallucination)
    Risk: Invalid data in model features leads to incorrect predictions and hallucinations
    Mitigation: Multi-stage validation ensures only clean data reaches ML systems
    Implementation: Data quality assurance prevents corrupted inputs to ML models

T6 (Intent Breaking)
    Risk: Execution path deviation through data manipulation or invalid inputs
    Mitigation: Deterministic filtering logic prevents unauthorized execution deviations
    Implementation: Validation ensures expected execution flow and data integrity

T8 (Repudiation & Untraceability)
    Risk: Silent data quality failures hide system issues and prevent root cause analysis
    Mitigation: Comprehensive logging provides audit trail for compliance and debugging
    Implementation: Log all filtering decisions with record IDs and rejection reasons

T9 (Identity Spoofing)
    Risk: Invalid status markers indicate tampered or spoofed records in pipeline
    Mitigation: Dual validation prevents spoofed records from entering ML pipeline
    Implementation: Metadata validation (status field) confirms record legitimacy

T12 (Insecure Output Handling)
    Risk: Outputting invalid data corrupts downstream systems and models
    Mitigation: Strict output validation ensures data quality guarantee to consumers
    Implementation: Only pass filtered records to ML models and storage systems
"""
    allure.attach(vulnerabilities_reference, 
                 name="Vulnerabilities Mitigated", 
                 attachment_type=allure.attachment_type.TEXT)
def attach_detection_analysis(detected, safe, undetected, total_inputs):
    """
    Attach detection analysis report to Allure with detected vs undetected patterns.
    
    Args:
        detected: List of detected malicious patterns (dicts with 'input', 'status', 'pattern')
        safe: List of safe patterns (dicts with 'input', 'status')
        undetected: List of undetected patterns (dicts with 'input', 'issue', 'suggestion', 'priority')
        total_inputs: Total number of inputs tested
    """
    detected_count = len(detected)
    safe_count = len(safe)
    undetected_count = len(undetected)
    detection_rate = (detected_count / total_inputs * 100) if total_inputs > 0 else 0
    
    # Color-coded report
    report = f"""<h1>🔍 Detection Analysis Report</h1>

<h2>📊 Summary Statistics</h2>

<table style="border-collapse: collapse; width: 100%; margin: 20px 0;">
<tr style="background-color: #f0f0f0;">
<th style="border: 1px solid #ddd; padding: 12px; text-align: left;">Metric</th>
<th style="border: 1px solid #ddd; padding: 12px; text-align: center;">Count</th>
<th style="border: 1px solid #ddd; padding: 12px; text-align: center;">Percentage</th>
</tr>
<tr>
<td style="border: 1px solid #ddd; padding: 12px;">Total Inputs Tested</td>
<td style="border: 1px solid #ddd; padding: 12px; text-align: center;"><strong>{total_inputs}</strong></td>
<td style="border: 1px solid #ddd; padding: 12px; text-align: center;">100%</td>
</tr>
<tr style="background-color: #c8e6c9;">
<td style="border: 1px solid #ddd; padding: 12px;">✅ Detected Threats</td>
<td style="border: 1px solid #ddd; padding: 12px; text-align: center;"><strong>{detected_count}</strong></td>
<td style="border: 1px solid #ddd; padding: 12px; text-align: center;"><strong>{detection_rate:.1f}%</strong></td>
</tr>
<tr style="background-color: #bbdefb;">
<td style="border: 1px solid #ddd; padding: 12px;">🔵 Safe Patterns</td>
<td style="border: 1px solid #ddd; padding: 12px; text-align: center;"><strong>{safe_count}</strong></td>
<td style="border: 1px solid #ddd; padding: 12px; text-align: center;"><strong>{safe_count/total_inputs*100:.1f}%</strong></td>
</tr>
<tr style="background-color: #ffcdd2;">
<td style="border: 1px solid #ddd; padding: 12px;">❌ Undetected (False Negatives)</td>
<td style="border: 1px solid #ddd; padding: 12px; text-align: center;"><strong>{undetected_count}</strong></td>
<td style="border: 1px solid #ddd; padding: 12px; text-align: center;"><strong>{undetected_count/total_inputs*100:.1f}%</strong></td>
</tr>
</table>

<hr style="margin: 30px 0; border: 2px solid #ddd;">

<h2>✅ Detected Patterns (Successfully Blocked)</h2>
<p style="color: #2e7d32; font-weight: bold;">Malicious inputs successfully blocked by guardrails:</p>

"""
    
    if detected:
        report += '<ul style="margin: 20px 0; padding-left: 20px;">'
        for item in detected:
            report += f"""<li style="margin: 10px 0; padding: 10px; background-color: #f1f8e9; border-left: 4px solid #4caf50;">
<strong>✓ {item['input']}</strong><br>
<small style="color: #555;">Status: {item['status']}</small><br>
<small style="color: #555;">Pattern: {item.get('pattern', 'N/A')}</small>
</li>"""
        report += '</ul>'
    else:
        report += '<p style="color: #999;">No detected patterns in this test.</p>'
    
    report += """<hr style="margin: 30px 0; border: 2px solid #ddd;">

<h2>🔵 Safe Patterns (Correctly Allowed)</h2>
<p style="color: #1565c0; font-weight: bold;">Legitimate inputs correctly allowed through:</p>

"""
    
    if safe:
        report += '<ul style="margin: 20px 0; padding-left: 20px;">'
        for item in safe:
            report += f"""<li style="margin: 10px 0; padding: 10px; background-color: #e3f2fd; border-left: 4px solid #2196f3;">
<strong>● {item['input']}</strong><br>
<small style="color: #555;">Status: {item['status']}</small><br>
<small style="color: #555;">Type: Benign query | False Positives: None</small>
</li>"""
        report += '</ul>'
    else:
        report += '<p style="color: #999;">No safe patterns in this test.</p>'
    
    report += """<hr style="margin: 30px 0; border: 2px solid #ddd;">

<h2>❌ Undetected Patterns (Known Gaps)</h2>
<p style="color: #c62828; font-weight: bold;">Malicious inputs that escaped detection - requires fixes:</p>

"""
    
    if undetected:
        report += '<ul style="margin: 20px 0; padding-left: 20px;">'
        for i, item in enumerate(undetected, 1):
            priority_color = "#ff6f00" if item['priority'] == "HIGH" else "#fbc02d" if item['priority'] == "MEDIUM" else "#9e9e9e"
            report += f"""<li style="margin: 15px 0; padding: 15px; background-color: #ffe0b2; border-left: 4px solid {priority_color};">
<strong>⚠ Gap #{i}: {item['input']}</strong><br>
<div style="margin-top: 8px; color: #333;">
<strong>Issue:</strong> {item['issue']}<br>
<strong>Suggestion:</strong> {item['suggestion']}<br>
<strong>Implementation:</strong> {item.get('implementation', 'See suggestion above')}<br>
<strong style="color: {priority_color};">Priority: {item['priority']}</strong>
</div>
</li>"""
        report += '</ul>'
    else:
        report += '<p style="color: #2e7d32; font-weight: bold;">✓ No undetected patterns - all tested inputs behave as expected!</p>'
    
    report += """<hr style="margin: 30px 0; border: 2px solid #ddd;">

<h2>🎯 Improvement Roadmap</h2>
<div style="margin: 20px 0;">
<p><strong style="color: #ff6f00;">🔴 HIGH Priority</strong> - Critical detection gaps causing 20%+ miss rate</p>
<p><strong style="color: #fbc02d;">🟡 MEDIUM Priority</strong> - Secondary attack vectors with moderate impact</p>
<p><strong style="color: #9e9e9e;">⚫ LOW Priority</strong> - Edge case improvements for completeness</p>
</div>

<hr style="margin: 30px 0; border: 2px solid #ddd;">
<p style="text-align: center; color: #999; font-size: 12px;"><em>Report generated by detection analysis system</em></p>
"""
    
    allure.attach(
        report,
        name="🔍 Detection Analysis",
        attachment_type=allure.attachment_type.HTML
    )
def attach_undetected_gap_with_mitigation(pattern_name, malicious_input, issue, suggestion, implementation, priority, mitigation_steps):
    """
    Attach individual undetected pattern gap with specific mitigation steps.
    
    Args:
        pattern_name: Name of the undetected pattern (e.g., "Special Character Obfuscation")
        malicious_input: The actual malicious input that wasn't detected
        issue: Why it wasn't detected
        suggestion: What to change
        implementation: How to implement the fix
        priority: HIGH/MEDIUM/LOW
        mitigation_steps: List of dicts with 'step' and 'action' keys
    """
    priority_color = "#ff6f00" if priority == "HIGH" else "#fbc02d" if priority == "MEDIUM" else "#9e9e9e"
    priority_emoji = "🔴" if priority == "HIGH" else "🟡" if priority == "MEDIUM" else "⚫"
    
    report = f"""<div style="border-left: 5px solid {priority_color}; padding: 20px; background-color: #fafafa; margin: 20px 0;">

<h2>{priority_emoji} UNDETECTED GAP: {pattern_name}</h2>

<h3>❌ Malicious Input Not Caught:</h3>
<pre style="background-color: #fff3e0; padding: 10px; border-radius: 4px; overflow-x: auto;">
{malicious_input}
</pre>

<h3>⚠️ Issue:</h3>
<p style="color: #d32f2f; font-weight: bold;">{issue}</p>

<h3>💡 Suggested Fix:</h3>
<p>{suggestion}</p>

<h3>🔧 Implementation Details:</h3>
<p><code>{implementation}</code></p>

<h3>📋 Priority: <span style="color: {priority_color}; font-weight: bold;">{priority}</span></h3>

<h3>✅ Mitigation Steps to Implement:</h3>
<ol style="margin: 15px 0; padding-left: 20px;">
"""
    
    for step in mitigation_steps:
        report += f"""<li style="margin: 10px 0; padding: 8px; background-color: white; border-radius: 4px;">
<strong>{step['step']}</strong><br>
<small>{step['action']}</small>
</li>
"""
    
    report += """</ol>
</div>
"""
    
    allure.attach(
        report,
        name=f"{priority_emoji} GAP: {pattern_name}",
        attachment_type=allure.attachment_type.HTML
    )
    
def attach_guardrail_action(threats_detected):
    """Attach guardrail action taken to Allure report.
    
    Args:
        threats_detected: List of detected threat types (e.g., ['prompt_injection'])
    """
    action_details = f"""<div style="border-left: 4px solid #ff6f00; padding: 15px; background-color: #fff3e0; margin: 10px 0;">
<h3>⛔ Guardrail Action: BLOCKED</h3>
<table style="width: 100%; border-collapse: collapse;">
<tr style="background-color: #ffe0b2;">
<th style="border: 1px solid #ddd; padding: 10px; text-align: left;">Property</th>
<th style="border: 1px solid #ddd; padding: 10px; text-align: left;">Value</th>
</tr>
<tr>
<td style="border: 1px solid #ddd; padding: 10px;"><strong>Action Taken</strong></td>
<td style="border: 1px solid #ddd; padding: 10px;"><span style="background-color: #ff6f00; color: white; padding: 4px 8px; border-radius: 3px; font-weight: bold;">BLOCK</span></td>
</tr>
<tr>
<td style="border: 1px solid #ddd; padding: 10px;"><strong>Threats Detected</strong></td>
<td style="border: 1px solid #ddd; padding: 10px;">"""
    
    if isinstance(threats_detected, list):
        threats_html = ', '.join([f'<code style="background-color: #ffb3ba; padding: 3px 6px; border-radius: 2px;">{threat}</code>' for threat in threats_detected])
        action_details += threats_html
    else:
        action_details += f'<code style="background-color: #ffb3ba; padding: 3px 6px; border-radius: 2px;">{threats_detected}</code>'
    
    action_details += """</td></tr></table></div>"""
    
    allure.attach(action_details, name="⛔ Guardrail Action", attachment_type=allure.attachment_type.HTML)