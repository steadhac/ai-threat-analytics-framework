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
