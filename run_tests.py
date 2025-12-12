#!/usr/bin/env python3
"""
AI & Threat Analytics Test Runner
Entry point for executing the test suite
"""
import sys
import os
import argparse
import yaml
import pytest
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.logger import get_logger

logger = get_logger(__name__)


def load_config(config_path: str = "config/settings.yaml") -> dict:
    """Load configuration from YAML file."""
    config_file = PROJECT_ROOT / config_path
    
    if not config_file.exists():
        logger.warning(f"Config file not found: {config_file}")
        return {}
    
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    logger.info(f"Loaded configuration from {config_file}")
    return config


def setup_environment():
    """Set up test environment."""
    # Create reports directory if it doesn't exist
    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    logger.info("Environment setup complete")


def main():
    """Main entry point for test execution."""
    parser = argparse.ArgumentParser(
        description="AI & Threat Analytics Automation Testing Framework"
    )
    
    parser.add_argument(
        "--suite",
        choices=["all", "ai", "pipelines", "security", "integration"],
        default="all",
        help="Test suite to run"
    )
    
    parser.add_argument(
        "--markers",
        type=str,
        help="Pytest markers to filter tests (e.g., 'not slow')"
    )
    
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Number of parallel workers (default: 1)"
    )
    
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Generate coverage report"
    )
    
    parser.add_argument(
        "--allure",
        action="store_true",
        help="Generate Allure report"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase verbosity"
    )
    
    args = parser.parse_args()
    
    # Setup
    setup_environment()
    config = load_config()
    
    # Build pytest arguments
    pytest_args = []
    
    # Select test suite
    if args.suite == "ai":
        pytest_args.append("tests_ai/")
    elif args.suite == "pipelines":
        pytest_args.append("tests_pipelines/")
    elif args.suite == "security":
        pytest_args.extend(["-k", "security or guardrail or pii"])
    elif args.suite == "integration":
        pytest_args.append("tests_pipelines/test_integration_ml.py")
    else:
        pytest_args.extend(["tests_ai/", "tests_pipelines/"])
    
    # Markers
    if args.markers:
        pytest_args.extend(["-m", args.markers])
    
    # Parallel execution
    if args.parallel > 1:
        pytest_args.extend(["-n", str(args.parallel)])
    
    # Coverage
    if args.coverage:
        pytest_args.extend([
            "--cov=core",
            "--cov=tests_ai",
            "--cov=tests_pipelines",
            "--cov-report=html",
            "--cov-report=term"
        ])
    
    # Allure reporting
    if args.allure:
        pytest_args.extend([
            "--alluredir=reports/allure-results"
        ])
    
    # Verbosity
    if args.verbose > 0:
        pytest_args.append("-" + "v" * args.verbose)
    
    # HTML report
    pytest_args.extend([
        "--html=reports/results.html",
        "--self-contained-html"
    ])
    
    # Additional options
    pytest_args.extend([
        "--tb=short",  # Shorter traceback format
        "--color=yes"  # Colored output
    ])
    
    logger.info(f"Running tests with arguments: {' '.join(pytest_args)}")
    
    # Run tests
    exit_code = pytest.main(pytest_args)
    
    # Generate Allure report if requested
    if args.allure and exit_code == 0:
        try:
            import subprocess
            subprocess.run([
                "allure", "generate",
                "reports/allure-results",
                "-o", "reports/allure-report",
                "--clean"
            ])
            logger.info("Allure report generated at reports/allure-report/")
        except FileNotFoundError:
            logger.warning("Allure command not found. Install Allure to generate reports.")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
