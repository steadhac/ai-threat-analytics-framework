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