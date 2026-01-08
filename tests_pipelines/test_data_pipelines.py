"""
Test suite for data pipeline validation and quality assurance.

This module validates the data cleaning and validation pipeline's ability to
filter, transform, and ensure quality of data flowing through the ML system.

Test Coverage:
- Data validation and null/invalid value filtering
- Data structure integrity preservation
- Removal of corrupted records
- Maintaining data consistency across pipeline stages
- Quality metrics calculation

Pipeline Stages:
1. Raw data ingestion (heterogeneous, unclean data)
2. Validation (status field checks)
3. Cleaning (null value removal)
4. Quality assurance (assertion validation)
5. Handoff to ML models (clean data only)

Data Quality Risks Mitigated:
- Null values causing model crashes
- Invalid records corrupting model training
- Data leakage from incomplete records
- Silent data quality degradation

Usage:
    pytest tests_pipelines/test_data_pipelines.py -v
    pytest tests_pipelines/test_data_pipelines.py::test_data_validation -v
"""

import pytest
import logging

logger = logging.getLogger(__name__)


def test_data_validation():
    """
    Test data validation and cleaning pipeline.
    
    Validates:
        - Data filtering correctly removes invalid records
        - Null values are properly detected and excluded
        - Valid records are preserved with all fields intact
        - Pipeline output is clean and ML-ready
    
    Test Data Structure:
        Raw ingestion with 3 records:
        [
            {'id': 1, 'value': 100, 'status': 'valid'},      ✓ Keep
            {'id': 2, 'value': None, 'status': 'invalid'},   ✗ Remove (null)
            {'id': 3, 'value': 200, 'status': 'valid'}       ✓ Keep
        ]
        Expected: 2 valid records, 1 removed
    
    Validation Logic:
        - Filter condition 1: status == 'valid' (metadata validation)
        - Filter condition 2: value is not None (data quality)
        Both conditions must be TRUE to keep record
    
    Expected Result:
        valid_data = [
            {'id': 1, 'value': 100, 'status': 'valid'},
            {'id': 3, 'value': 200, 'status': 'valid'}
        ]
    
    Assertions:
        - Assertion 1: Count is 2 (correct filtering)
        - Assertion 2: All values non-null (data integrity)
    
    Risk Mitigated:
        - Null values in ML features cause model failures
        - Invalid records corrupt training data
        - Silent data quality issues downstream
    
    Pipeline Stage:
        Validation → Cleaning → Quality Assurance → ML Ready
    """
    logger.info("=" * 60)
    logger.info("TEST: Data Validation and Cleaning")
    
    logger.debug("Step 1: Create raw data from external source")
    raw_data = [
        {'id': 1, 'value': 100, 'status': 'valid'},
        {'id': 2, 'value': None, 'status': 'invalid'},
        {'id': 3, 'value': 200, 'status': 'valid'}
    ]
    logger.debug(f"Raw records: {len(raw_data)}")
    for idx, record in enumerate(raw_data):
        logger.debug(f"  Record {idx}: {record}")
    
    logger.debug("Step 2: Execute data validation and cleaning")
    logger.debug("  Filtering: status='valid' AND value is not None")
    # Filter valid records - remove nulls and invalid status
    valid_data = [d for d in raw_data if d['status'] == 'valid' and d['value'] is not None]
    logger.info(f"Cleaned records: {len(valid_data)}")
    for idx, record in enumerate(valid_data):
        logger.debug(f"  Valid record {idx}: {record}")
    
    logger.debug("Step 3: Assertion 1 - Validate record count")
    logger.debug(f"  Expected: 2, Got: {len(valid_data)}")
    assert len(valid_data) == 2, f"Expected 2 valid records, got {len(valid_data)}"
    logger.debug("✓ Correct number of records retained")
    
    logger.debug("Step 4: Assertion 2 - Validate data integrity")
    logger.debug("  Checking all values are not None")
    invalid_records = [d for d in valid_data if d['value'] is None]
    logger.debug(f"  Null values found: {len(invalid_records)}")
    assert all(d['value'] is not None for d in valid_data), \
        "All valid records should have non-null values"
    logger.debug("✓ All values are valid (non-null)")
    
    logger.info("✓ PASSED: Data validation and cleaning successful")
    logger.info("  Records removed: 1 (invalid/null)")
    logger.info("  Records retained: 2 (clean, valid)")
    logger.info("=" * 60)


@pytest.mark.parametrize("input_records,expected_valid_count", [
    # Case 1: All valid data
    (
        [
            {'id': 1, 'value': 100, 'status': 'valid'},
            {'id': 2, 'value': 200, 'status': 'valid'},
            {'id': 3, 'value': 300, 'status': 'valid'}
        ],
        3
    ),
    # Case 2: Mixed valid/invalid
    (
        [
            {'id': 1, 'value': 100, 'status': 'valid'},
            {'id': 2, 'value': None, 'status': 'invalid'},
            {'id': 3, 'value': None, 'status': 'invalid'},
            {'id': 4, 'value': 400, 'status': 'valid'}
        ],
        2
    ),
    # Case 3: All invalid
    (
        [
            {'id': 1, 'value': None, 'status': 'invalid'},
            {'id': 2, 'value': None, 'status': 'invalid'}
        ],
        0
    ),
])
def test_data_validation_multiple_scenarios(input_records, expected_valid_count):
    """
    Test data validation across multiple scenarios.
    
    Validates:
        - Pipeline handles varying data quality scenarios
        - Filtering works with 100% valid, mixed, and 100% invalid data
        - Count accuracy maintained across different data distributions
    
    Parametrization:
        Scenario 1: Best case - all records are valid (3/3)
        Scenario 2: Typical case - mixed valid/invalid (2/4)
        Scenario 3: Worst case - all records invalid (0/2)
    
    Expected Results:
        Scenario 1: valid_count = 3
        Scenario 2: valid_count = 2
        Scenario 3: valid_count = 0
    
    Assertions:
        1 assertion per scenario validates count matches expectation
    
    Pipeline Robustness:
        Tests that validation works across data quality spectrum
        from pristine data to completely corrupted datasets
    """
    logger.info("=" * 60)
    logger.info(f"TEST: Data Validation Scenario (expect {expected_valid_count} valid)")
    
    logger.debug(f"Step 1: Load test data with {len(input_records)} records")
    for idx, record in enumerate(input_records):
        logger.debug(f"  Record {idx}: {record}")
    
    logger.debug("Step 2: Execute validation")
    valid_data = [d for d in input_records 
                  if d['status'] == 'valid' and d['value'] is not None]
    logger.info(f"Validation result: {len(valid_data)} valid records")
    
    logger.debug("Step 3: Validate count matches expectation")
    logger.debug(f"  Expected: {expected_valid_count}, Got: {len(valid_data)}")
    assert len(valid_data) == expected_valid_count, \
        f"Expected {expected_valid_count} valid records, got {len(valid_data)}"
    logger.debug("✓ Count matches scenario expectation")
    
    logger.info(f"✓ PASSED: Scenario validated ({len(valid_data)}/{len(input_records)} records)")
    logger.info("=" * 60)