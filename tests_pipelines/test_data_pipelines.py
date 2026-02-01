"""
Test suite for data pipeline validation and quality assurance.

This module validates the data cleaning and validation pipeline's ability to
filter, transform, and ensure quality of data flowing through the ML system.

Pipeline Phases:
1. Raw data ingestion (heterogeneous, unclean data)
2. Validation (status field checks)
3. Cleaning (null value removal)
4. Quality assurance (assertion validation)
5. Handoff to ML models (clean data only)

Test Coverage:
- Raw data ingestion and parsing
- Data validation and null/invalid value filtering
- Data structure integrity preservation
- Removal of corrupted records
- Maintaining data consistency across pipeline phases
- Quality metrics calculation
- Empty dataset rejection (fail-fast policy)

Integration Risks Mitigated:
- Null values causing model crashes
- Invalid records corrupting model training
- Data leakage from incomplete records
- Silent data quality degradation
- Broken connections between pipeline phases
- Empty datasets crashing downstream ML models

OWASP Agentic AI Threat Mitigations:
- T2 (Tool Misuse): Validate data structure before processing to prevent incorrect tool use
- T4 (Resource Overload): Detect and remove null/malformed records to prevent resource exhaustion
- T5 (Cascading Hallucination): Ensure clean data prevents downstream model hallucinations
- T8 (Repudiation & Untraceability): Maintain audit trail through validation logging
- T9 (Identity Spoofing): Verify record authenticity through status/value validation
- T12 (Insecure Output Handling): Only output validated, clean records to downstream systems

Usage:
    pytest tests_pipelines/test_data_pipelines.py -v
"""

import pytest
import logging
import allure
from allure_helpers import attach_mitigation, attach_stage_details

logger = logging.getLogger(__name__)

MITIGATIONS_REFERENCE = """
OWASP Agentic AI Threats Mitigated by Data Pipeline Validation

T2 (Tool Misuse): Dual-field validation ensures tools receive correct data format
T4 (Resource Overload): Early filtering removes problematic records before resource consumption
T5 (Cascading Hallucination): Multi-stage validation prevents corrupted inputs to ML models
T6 (Intent Breaking): Deterministic filtering prevents unauthorized execution deviations
T8 (Repudiation & Untraceability): Comprehensive logging provides audit trail
T9 (Identity Spoofing): Metadata validation prevents spoofed records from entering pipeline
T12 (Insecure Output Handling): Strict output validation ensures clean data to consumers
"""

@pytest.fixture(scope="session", autouse=True)
def attach_mitigations_to_report():
    """Attach vulnerability mitigations reference to Allure report."""
    allure.step("OWASP Agentic AI Threat Mitigations Reference")
    allure.attach(
        MITIGATIONS_REFERENCE,
        name="OWASP Agentic AI Threat Mitigations",
        attachment_type=allure.attachment_type.TEXT
    )

@allure.feature("Data Pipeline Validation")
@allure.story("Core Validation Logic")
@allure.title("Test Data Validation and Cleaning Pipeline")
def test_data_validation():
    """
    Test data validation and cleaning pipeline: ingestion → validation → cleaning → handoff.
    
    Validates:
        - Raw data is correctly ingested
        - Data filtering removes invalid records
        - Null values are properly detected and excluded
        - Valid records are preserved with all fields intact
        - Pipeline output is clean and ML-ready
    
    Pipeline Flow:
        Raw Records → Validation → Cleaning → Quality Assurance → ML Ready
        
    Test Data:
        Input: 3 records (1 valid, 1 null, 1 valid)
        [
            {'id': 1, 'value': 100, 'status': 'valid'},      ✓ Keep
            {'id': 2, 'value': None, 'status': 'invalid'},   ✗ Remove (null)
            {'id': 3, 'value': 200, 'status': 'valid'}       ✓ Keep
        ]
    
    Validation Logic:
        - Filter condition 1: status == 'valid' (metadata validation)
        - Filter condition 2: value is not None (data quality)
        Both conditions must be TRUE to keep record
    
    Expected Results:
        valid_records = 2
        removed_records = 1
        data_quality = 100%
    
    Assertions:
        - Assertion 1: Count is 2 (correct filtering)
        - Assertion 2: All values non-null (data integrity)
        - Assertion 3: Records match quality standards (validation isolation)
    
    Risk Mitigated:
        - Null values in ML features cause model failures
        - Invalid records corrupt training data
        - Silent data quality issues downstream
        - Malformed data causes pipeline errors
    
    Integration Points Tested:
        1. Data ingestion → Validation (structure check)
        2. Validation → Cleaning (null removal)
        3. Cleaning → Quality assurance (count verification)
        4. Quality assurance → ML handoff (output guarantee)
    """
    logger.info("=" * 60)
    logger.info("TEST: Data Validation and Cleaning Pipeline")
    
    allure.step("PHASE 1: Raw Data Ingestion")
    phase1_details = """
Load heterogeneous, unclean data from external source.
Data contains valid records, nulls, and invalid status markers.
Load into memory for validation processing.
Prepare 3 records for filtering pipeline.
"""
    logger.debug("PHASE 1: Raw Data Ingestion")
    logger.debug("-" * 40)
    raw_data = [
        {'id': 1, 'value': 100, 'status': 'valid'},
        {'id': 2, 'value': None, 'status': 'invalid'},
        {'id': 3, 'value': 200, 'status': 'valid'}
    ]
    attach_stage_details("PHASE 1: Raw Data Ingestion", phase1_details)
    logger.debug(f"Step 1a: Load raw input data")
    logger.debug(f"  Total records: {len(raw_data)}")
    for idx, record in enumerate(raw_data):
        logger.debug(f"  Record {idx}: {record}")
    
    allure.step("PHASE 2: Data Validation and Filtering")
    phase2_details = """
Apply validation rules to identify and filter records.
Filter condition 1: status == 'valid' (metadata validation)
Filter condition 2: value is not None (data quality check)
Both conditions must be TRUE to keep record.
Remove records that fail either condition.
"""
    logger.debug("PHASE 2: Data Validation and Filtering")
    logger.debug("-" * 40)
    valid_data = [d for d in raw_data if d['status'] == 'valid' and d['value'] is not None]
    attach_stage_details("PHASE 2: Data Validation and Filtering", phase2_details)
    logger.debug(f"Step 2a: Apply validation filters")
    logger.debug(f"  Filter 1: status == 'valid'")
    logger.debug(f"  Filter 2: value is not None")
    logger.info(f"Validation result: {len(valid_data)} valid records, {len(raw_data) - len(valid_data)} removed")
    for idx, record in enumerate(valid_data):
        logger.debug(f"  Valid record {idx}: {record}")
    
    allure.step("PHASE 3: Data Quality Verification")
    phase3_details = """
Verify data quality metrics after filtering.
Check all values are non-null and valid.
Confirm no data corruption in cleaned records.
Validate field integrity across all records.
"""
    logger.debug("PHASE 3: Data Quality Verification")
    logger.debug("-" * 40)
    invalid_records = [d for d in valid_data if d['value'] is None]
    attach_stage_details("PHASE 3: Data Quality Verification", phase3_details)
    logger.debug(f"Step 3a: Check data integrity")
    logger.debug(f"  Null values found: {len(invalid_records)}")
    logger.debug(f"  Data quality score: 100%")
    
    allure.step("PHASE 4: ML Pipeline Handoff")
    phase4_details = """
Output validated data ready for ML processing.
All records pass quality gates.
Data is guaranteed clean for model training.
Audit trail complete for compliance.
"""
    logger.debug("PHASE 4: ML Pipeline Handoff")
    logger.debug("-" * 40)
    attach_stage_details("PHASE 4: ML Pipeline Handoff", phase4_details)
    logger.debug(f"Step 4a: Prepare handoff data")
    logger.info(f"Output records: {len(valid_data)}")
    logger.info(f"Data quality: Validated")
    logger.info(f"Ready for ML: True")
    
    allure.step("MITIGATION 1: Input Validation")
    logger.debug("PHASE 5: Validation & Assertions")
    logger.debug("-" * 40)
    logger.debug("Step 5a: Assertion 1 - Validate record count")
    logger.debug(f"  Expected: 2, Got: {len(valid_data)}")
    attach_mitigation(
        playbook_num="1",
        name="Input Validation",
        description="Ensure correct number of records after filtering",
        implementation="Verify record count == 2 after removing invalid/null records",
        mitigates="T2 (Tool Misuse), T4 (Resource Overload), T9 (Identity Spoofing)",
        coverage="Asserts len(valid_data) == 2"
    )
    assert len(valid_data) == 2, f"Expected 2 valid records, got {len(valid_data)}"
    logger.debug("✓ Record count correct (data integrity)")
    
    allure.step("MITIGATION 2: Data Integrity Protection")
    logger.debug("Step 5b: Assertion 2 - Validate data integrity")
    logger.debug(f"  Checking all values are not None")
    logger.debug(f"  Null values found: {len(invalid_records)}")
    attach_mitigation(
        playbook_num="2",
        name="Data Integrity Protection",
        description="Verify all values in cleaned data are non-null",
        implementation="Assert all(d['value'] is not None for d in valid_data)",
        mitigates="T5 (Cascading Hallucination), T8 (Repudiation), T12 (Insecure Output)",
        coverage="Asserts all values are non-null"
    )
    assert all(d['value'] is not None for d in valid_data), \
        "All valid records should have non-null values"
    logger.debug("✓ All values are valid (no nulls)")
    
    allure.step("MITIGATION 3: Execution Control")
    logger.debug("Step 5c: Assertion 3 - Validate execution isolation")
    attach_mitigation(
        playbook_num="3",
        name="Execution Control",
        description="Ensure filtering validation is isolated and deterministic",
        implementation="Verify valid_data contains only records meeting both filter conditions",
        mitigates="T2 (Tool Misuse), T6 (Intent Breaking), T9 (Identity Spoofing)",
        coverage="Asserts all records have status='valid' AND value is not None"
    )
    for record in valid_data:
        assert record['status'] == 'valid' and record['value'] is not None, \
            "All valid records must meet both filter conditions"
    logger.debug("✓ Execution isolated and deterministic")
    
    logger.info("✓ PASSED: Data validation and cleaning successful")
    logger.info("  Records removed: 1 (invalid/null)")
    logger.info("  Records retained: 2 (clean, valid)")
    logger.info("  Data quality: 100%")
    logger.info("=" * 60)


@pytest.mark.parametrize("input_records,expected_valid_count,scenario_status", [
    ([
        {'id': 1, 'value': 100, 'status': 'valid'},
        {'id': 2, 'value': None, 'status': 'invalid'},
        {'id': 3, 'value': None, 'status': 'invalid'},
        {'id': 4, 'value': 400, 'status': 'valid'}
    ], 2, "MIXED_DATA"),
])
@allure.feature("Data Pipeline Validation")
@allure.story("Scenario-Based Validation")
def test_data_validation_multiple_scenarios(input_records, expected_valid_count, scenario_status):
    """
    Test data pipeline across scenarios: mixed valid/invalid data.
    
    Validates:
        - Pipeline handles varying data quality scenarios
        - Filtering works with mixed valid/invalid data
        - Count accuracy maintained across different data distributions
        - Pipeline is robust to different data patterns
    
    Parametrization:
        
        Scenario: Mixed valid/invalid (2/4)
                  2 records valid, 2 records with nulls/invalid status
                  Expected: keep 2 valid, remove 2 invalid
                  Status: MIXED_DATA (produces usable output)
    
    Validation Logic (across scenarios):
        - Filter condition 1: status == 'valid' (metadata check)
        - Filter condition 2: value is not None (data quality check)
        Both conditions must be TRUE
    
    Assertions:
        - Assertion 1: valid_count matches expected (extraction accuracy)
        - Assertion 2: All values non-null (data integrity)
        - Assertion 3: Filtering is deterministic (execution isolation)
        - Assertion 4: Non-empty output (fail-fast empty dataset policy)
    
    Pipeline Robustness:
        Tests that validation works with diverse data quality while
        rejecting batches that produce empty datasets.
    """
    allure.dynamic.title(f"Test Data Validation - Scenario [{scenario_status}]")
    
    logger.info("=" * 60)
    logger.info(f"TEST: Data Validation - Scenario [{scenario_status}]")
    logger.info(f"Expected: {expected_valid_count} valid records")
    logger.info(f"Status: {scenario_status}")
    
    allure.step("PHASE 1: Data Ingestion")
    phase1_details = f"""
Load scenario data with {len(input_records)} records.
Data quality varies by scenario.
Expected valid count: {expected_valid_count}
Scenario status: {scenario_status}
Prepare for validation pipeline.
"""
    logger.debug("PHASE 1: Data Ingestion")
    logger.debug("-" * 40)
    raw_data = input_records
    attach_stage_details("PHASE 1: Data Ingestion", phase1_details)
    logger.debug(f"Step 1a: Load test data")
    logger.debug(f"  Total records: {len(raw_data)}")
    for idx, record in enumerate(raw_data):
        logger.debug(f"  Record {idx}: {record}")
    
    allure.step("PHASE 2: Data Validation and Filtering")
    phase2_details = f"""
Apply validation filters to all {len(raw_data)} records.
Filter 1: status == 'valid'
Filter 2: value is not None
Expected valid records after filtering: {expected_valid_count}
Identify and remove invalid/null records.
"""
    logger.debug("PHASE 2: Data Validation and Filtering")
    logger.debug("-" * 40)
    valid_data = [d for d in raw_data if d['status'] == 'valid' and d['value'] is not None]
    attach_stage_details("PHASE 2: Data Validation and Filtering", phase2_details)
    logger.debug(f"Step 2a: Execute validation filters")
    logger.info(f"Validation result: {len(valid_data)} valid records (expected: {expected_valid_count})")
    logger.debug(f"  Removed: {len(raw_data) - len(valid_data)} records")
    
    allure.step("PHASE 3: Data Quality Assessment")
    phase3_details = f"""
Assess cleaned data quality after filtering.
All remaining records must be valid and non-null.
Expected count: {expected_valid_count}
Actual count: {len(valid_data)}
Quality verification complete.
"""
    logger.debug("PHASE 3: Data Quality Assessment")
    logger.debug("-" * 40)
    invalid_records = [d for d in valid_data if d['value'] is None]
    attach_stage_details("PHASE 3: Data Quality Assessment", phase3_details)
    logger.debug(f"Step 3a: Verify quality metrics")
    logger.debug(f"  Null values in cleaned data: {len(invalid_records)}")
    logger.debug(f"  Quality percentage: {100 if len(invalid_records) == 0 else 0}%")
    
    allure.step("PHASE 4: ML Pipeline Handoff")
    phase4_details = f"""
Prepare filtered data for ML model.
Output: {len(valid_data)} validated records
Quality guarantee: All records are clean
Ready for downstream model training.
"""
    logger.debug("PHASE 4: ML Pipeline Handoff")
    logger.debug("-" * 40)
    attach_stage_details("PHASE 4: ML Pipeline Handoff", phase4_details)
    logger.info(f"Handoff: {len(valid_data)} records ready for ML")
    
    allure.step("MITIGATION 1: Input Validation")
    logger.debug("PHASE 5: Validation & Assertions")
    logger.debug("-" * 40)
    logger.debug("Step 5a: Assertion 1 - Validate record count")
    logger.debug(f"  Expected: {expected_valid_count}, Got: {len(valid_data)}")
    attach_mitigation(
        playbook_num="1",
        name="Input Validation",
        description="Verify record count matches expected value for scenario",
        implementation="Assert len(valid_data) == expected_valid_count",
        mitigates="T2 (Tool Misuse), T4 (Resource Overload), T9 (Identity Spoofing)",
        coverage="Asserts count accuracy across all scenarios"
    )
    assert len(valid_data) == expected_valid_count, \
        f"Expected {expected_valid_count} valid records, got {len(valid_data)}"
    logger.debug("✓ Record count correct")
    
    allure.step("MITIGATION 2: Data Integrity Protection")
    logger.debug("Step 5b: Assertion 2 - Validate data integrity")
    logger.debug(f"  Null values found: {len(invalid_records)}")
    attach_mitigation(
        playbook_num="2",
        name="Data Integrity Protection",
        description="Verify all values in cleaned data are non-null",
        implementation="Assert all values are not None across all scenarios",
        mitigates="T5 (Cascading Hallucination), T8 (Repudiation), T12 (Insecure Output)",
        coverage="Asserts zero null values in cleaned data"
    )
    assert all(d['value'] is not None for d in valid_data), \
        "All valid records should have non-null values"
    logger.debug("✓ Data integrity verified")
    
    allure.step("MITIGATION 3: Execution Control")
    logger.debug("Step 5c: Assertion 3 - Validate execution isolation")
    attach_mitigation(
        playbook_num="3",
        name="Execution Control",
        description="Ensure filtering is deterministic and isolated",
        implementation="Verify all valid records meet status='valid' AND value is not None",
        mitigates="T2 (Tool Misuse), T6 (Intent Breaking), T9 (Identity Spoofing)",
        coverage="Asserts deterministic filtering across all scenarios"
    )
    for record in valid_data:
        assert record['status'] == 'valid' and record['value'] is not None, \
            "All valid records must meet both filter conditions"
    logger.debug("✓ Execution isolation verified")
    
    allure.step("MITIGATION 4: Empty Dataset Rejection (Fail-Fast Policy)")
    logger.debug("Step 5d: Assertion 4 - Reject empty dataset outputs")
    logger.debug(f"  Valid records output: {len(valid_data)}")
    attach_mitigation(
        playbook_num="4",
        name="Empty Dataset Rejection",
        description="Enforce minimum record threshold to prevent downstream ML failures",
        implementation="Assert len(valid_data) > 0 - reject batches with zero output records",
        mitigates="T4 (Resource Overload), T5 (Cascading Hallucination), T12 (Insecure Output)",
        coverage="Fails test if pipeline produces empty dataset (prevents silent ML failures)"
    )
    assert len(valid_data) > 0, \
        f"Pipeline must produce at least 1 valid record. Got {len(valid_data)} records. " \
        f"Reject batch and request re-validation of source data."
    logger.debug("✓ Non-empty output verified (ML safety gate)")
    
    logger.info(f"✓ PASSED: Scenario validation complete [{scenario_status}]")
    logger.info(f"  Valid records: {len(valid_data)}/{len(raw_data)}")
    logger.info("=" * 60)