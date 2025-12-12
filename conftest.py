# Pytest fixtures and configuration
import pytest
import yaml
from pathlib import Path


@pytest.fixture(scope="session")
def config():
    """Load configuration for tests."""
    config_path = Path(__file__).parent / "config" / "settings.yaml"
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    return config


@pytest.fixture(scope="session")
def test_data():
    """Load test data."""
    data_path = Path(__file__).parent / "config" / "test_data" / "sample_data.yaml"
    
    with open(data_path, 'r') as f:
        data = yaml.safe_load(f)
    
    return data


@pytest.fixture
def api_token(config):
    """Get API token from config or environment."""
    import os
    return os.getenv("security-platform_API_TOKEN", config["api"]["token"])


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Setup for each test."""
    # Setup code here
    yield
    # Teardown code here


# Pytest hooks
def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow"
    )
    config.addinivalue_line(
        "markers", "integration: integration tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test items during collection."""
    # Add markers automatically based on test location
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        if "test_llm" in str(item.fspath) or "test_classification" in str(item.fspath):
            item.add_marker(pytest.mark.ml)
