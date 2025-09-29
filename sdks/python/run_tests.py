#!/usr/bin/env python3
"""Test runner for AuthFramework Python SDK.

This script provides different test execution modes:
- Unit tests only (mocked, fast)
- Integration tests only (requires real server)
- All tests (unit + integration)
"""

import argparse
import asyncio
import sys
from pathlib import Path

import pytest


def main():
    """Main test runner entry point."""
    parser = argparse.ArgumentParser(description="Run AuthFramework SDK tests")
    parser.add_argument(
        "--mode",
        choices=["unit", "integration", "all"],
        default="unit",
        help="Test mode to run (default: unit)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Run with coverage reporting"
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=8088,
        help="Port for test server (integration tests only)"
    )
    
    args = parser.parse_args()
    
    # Build pytest arguments
    pytest_args = []
    
    if args.verbose:
        pytest_args.append("-v")
    
    if args.coverage:
        pytest_args.extend([
            "--cov=authframework",
            "--cov-report=html",
            "--cov-report=term-missing"
        ])
    
    # Select test paths based on mode
    if args.mode == "unit":
        pytest_args.extend([
            "tests/test_architecture.py",
            "tests/test_architecture_fixed.py",
            "-m", "not integration"
        ])
        print("🧪 Running unit tests (mocked)...")
        
    elif args.mode == "integration":
        pytest_args.extend([
            "tests/integration/",
            "-m", "integration"
        ])
        print(f"🚀 Running integration tests (requires server on port {args.server_port})...")
        
    elif args.mode == "all":
        pytest_args.append("tests/")
        print("🔄 Running all tests (unit + integration)...")
    
    # Set environment variable for server port
    import os
    os.environ["AUTH_FRAMEWORK_TEST_PORT"] = str(args.server_port)
    
    # Run tests
    exit_code = pytest.main(pytest_args)
    
    if exit_code == 0:
        print(f"✅ {args.mode.title()} tests passed!")
    else:
        print(f"❌ {args.mode.title()} tests failed!")
        sys.exit(exit_code)


if __name__ == "__main__":
    main()