# Contributing to CCTV VAPT

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

---

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please:

- Be respectful and constructive in communications
- Welcome diverse perspectives and experiences
- Focus on criticizing ideas, not individuals
- Report any violations to maintainers

---

## Getting Started

### Prerequisites

- Python 3.9+
- Virtual environment setup
- Git installed and configured
- GitHub account

### Setup Development Environment

```bash
# 1. Fork repository on GitHub
# (Click 'Fork' button on https://github.com/yourname/CCTV-VAPT-TOOLS)

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/CCTV-VAPT-TOOLS.git
cd CCTV-VAPT-TOOLS

# 3. Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/CCTV-VAPT-TOOLS.git

# 4. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 5. Install development dependencies
pip install -r requirements.txt

# 6. Setup pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

---

## Development Workflow

### Branch Naming Convention

Use descriptive names with the following format:

```
feature/description       # New feature
bugfix/description        # Bug fix
docs/description          # Documentation
refactor/description      # Code refactoring
test/description          # Testing improvements
```

**Examples:**
```bash
git checkout -b feature/add-pdf-reports
git checkout -b bugfix/fix-jwt-token-validation
git checkout -b docs/update-api-documentation
```

### Creating a Feature Branch

```bash
# Update main branch
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and commit regularly
git add .
git commit -m "Description of changes"

# Push to your fork
git push origin feature/your-feature-name
```

### Keeping Branch Updated

```bash
# Fetch latest from upstream
git fetch upstream

# Rebase on main
git rebase upstream/main

# Force push to your fork (only for your branches!)
git push origin feature/your-feature-name --force-with-lease
```

---

## Coding Standards

### Python Style Guide

We follow **PEP 8** with the following specifics:

- **Line length:** 100 characters (not 79)
- **Imports:** Followed by local imports separate
- **Docstrings:** Use triple quotes for all functions/classes

### Code Formatting

**Before committing, run:**

```bash
# Auto-format code
black backend/ tests/

# Check formatting
black --check backend/ tests/

# Sort imports
isort backend/ tests/

# Lint code
flake8 backend/ tests/

# Type checking
mypy backend/
```

### Style Examples

**Function Docstring:**
```python
def generate_report(scan_id: str, format: str = 'html') -> Report:
    """
    Generate a report for a completed scan.
    
    Args:
        scan_id: The unique identifier of the scan
        format: Output format (html, json, pdf). Defaults to 'html'
        
    Returns:
        Report: The generated report object
        
    Raises:
        ScanNotFoundError: If scan_id doesn't exist
        InvalidFormatError: If format is not supported
    """
    pass
```

**Class Docstring:**
```python
class ReportService:
    """
    Service layer for report generation and management.
    
    This service orchestrates the report generation workflow including
    data gathering, formatting, and file storage.
    
    Attributes:
        db_session: SQLAlchemy database session
        storage_path: Path for storing generated reports
    """
    pass
```

### Type Hints

All functions should have type hints:

```python
# Good
def calculate_score(vulnerabilities: List[Vulnerability]) -> float:
    pass

# Bad
def calculate_score(vulnerabilities):
    pass
```

### Code Organization

```python
# 1. Imports (stdlib, third-party, local)
import json
from typing import List, Dict, Optional
from datetime import datetime

import requests
from flask import Blueprint, request

from backend.core.models import Scan, Device
from backend.core.database import db

# 2. Constants
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30

# 3. Classes
class ReportService:
    def __init__(self):
        pass

# 4. Functions
def helper_function():
    pass

# 5. Main block
if __name__ == '__main__':
    pass
```

---

## Commit Message Guidelines

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style (formatting, missing semicolons, etc.)
- `refactor`: Code refactoring without feature/fix
- `perf`: Performance improvements
- `test`: Test additions or modifications
- `chore`: Build, CI/CD, dependencies

### Scope

Module or component affected:
```
feat(reports): add PDF export functionality
fix(auth): validate JWT expiration time
docs(api): update endpoint documentation
test(models): add scan model tests
```

### Examples

**Good commits:**
```
feat(reports): add PDF export with watermark support

- Implement weasyprint-based PDF generation
- Add watermark with organization logo
- Include tables of contents for long reports

Closes #123
```

```
fix(auth): validate JWT token expiration

The token expiration field was not being properly validated
on API requests, allowing use of expired tokens.

Closes #456
```

**Bad commits:**
```
fix: stuff
updated code
wip
asdf
```

---

## Testing Requirements

### Writing Tests

All new features must include tests:

```python
# tests/unit/test_reports.py
import pytest

@pytest.mark.unit
def test_report_generation(db):
    """Test that reports are generated correctly"""
    # Arrange
    scan = create_test_scan()
    
    # Act
    report = ReportService().generate_report(scan.scan_id)
    
    # Assert
    assert report is not None
    assert report.format == 'html'
    assert report.file_path exists
```

### Test Coverage

- **Minimum coverage:** 50%
- **Target coverage:** 80%+
- **Coverage command:**

```bash
pytest --cov=backend --cov-report=html
open htmlcov/index.html  # View coverage report
```

### Test Markers

Use pytest markers for organization:

```python
@pytest.mark.unit
def test_config_loading():
    pass

@pytest.mark.integration
@pytest.mark.requires_db
def test_scan_creation():
    pass

@pytest.mark.e2e
@pytest.mark.slow
def test_complete_workflow():
    pass
```

### Running Tests

```bash
# All tests
pytest

# Unit tests only
pytest -m unit

# With verbose output
pytest -v

# Stop on first failure
pytest -x

# Last 5 failed tests
pytest --lf

# Specific test file
pytest tests/unit/test_models.py

# Specific test
pytest tests/unit/test_models.py::test_scan_model_creation
```

---

## Pull Request Process

### Before Submitting a PR

1. **Update your branch:** `git rebase upstream/main`
2. **Run all checks:**
   ```bash
   black backend/ tests/
   flake8 backend/ tests/
   mypy backend/
   pytest --cov=backend
   ```
3. **Verify no breaking changes**
4. **Update documentation** if needed
5. **Add/update tests** for your changes

### Submitting a PR

1. **Push to your fork:** `git push origin feature/your-feature`
2. **Create PR on GitHub:**
   - Use a descriptive title
   - Reference related issues (#123)
   - Describe changes in detail
   - Include screenshots if applicable

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] New feature
- [ ] Bug fix
- [ ] Documentation update
- [ ] Breaking change

## Related Issues
Closes #123

## Testing Done
- [ ] Unit tests added
- [ ] Integration tests added
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Tests passing
- [ ] No breaking changes
```

### PR Review Process

- At least 1 approval required before merge
- All checks must pass (tests, linting, coverage)
- No merge conflicts
- Code review comments must be addressed

---

## Reporting Bugs

### Bug Report Template

```markdown
## Description
Clear description of the bug

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: [e.g. Ubuntu 22.04]
- Python: [e.g. 3.11.0]
- VAPT: [e.g. 2.0.0]

## Additional Context
Logs, screenshots, etc.
```

### Reporting Security Issues

⚠️ **Do NOT create public issues for security vulnerabilities**

Email: security@vapt.example.com

---

## Feature Requests

### Feature Request Template

```markdown
## Description
Clear description of the desired feature

## Use Case
Why do you need this feature?

## Implementation Ideas (Optional)
Your thoughts on how to implement this

## Additional Context
Mockups, examples, etc.
```

---

## Project Structure

**Key directories:**

```
backend/
  ├── core/              # Core modules (config, db, models)
  ├── api/               # REST API endpoints
  ├── modules/           # Scanning functionality
  ├── tasks/             # Celery async tasks
  └── migrations/        # Database migrations

tests/
  ├── unit/              # Unit tests
  ├── integration/       # Integration tests
  └── e2e/               # End-to-end tests

docs/                    # Documentation
frontend/               # Web UI
```

---

## Resources

- **Documentation:** [docs/](../docs/)
- **API Reference:** [docs/API.md](../docs/API.md)
- **Architecture:** [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)
- **Setup Guide:** [docs/SETUP.md](../docs/SETUP.md)

---

## Questions?

- GitHub Issues for bugs/features
- GitHub Discussions for questions
- Email: dev@vapt.example.com

---

**Thank you for contributing! 🎉**
