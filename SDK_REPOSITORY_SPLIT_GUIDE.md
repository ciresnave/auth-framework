# SDK Repository Split Guide

This document outlines the process for splitting the Python and JavaScript SDKs from the main AuthFramework repository into their own independent repositories.

## Overview

The SDKs are being split to provide:
- **Focused Development**: Each SDK can have its own release cycle and versioning
- **Smaller Downloads**: Users only clone the SDK they need
- **Independent CI/CD**: Separate testing and deployment pipelines
- **Better Collaboration**: SDK-specific contributors don't need the full monorepo
- **Package Management**: Direct publishing to PyPI and npm without monorepo complexity

## Repository Structure

### Python SDK Repository: `ciresnave/authframework-python`

```
authframework-python/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── .vscode/
│   └── settings.json
├── src/
│   └── authframework/
│       ├── __init__.py
│       ├── client.py
│       ├── _auth.py
│       ├── _admin.py
│       ├── _base.py
│       ├── _tokens.py
│       ├── exceptions.py
│       ├── models/
│       └── integrations/
├── tests/
├── examples/
├── docs/
├── pyproject.toml
├── pyrightconfig.json
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
└── authframework-python-sdk.code-workspace
```

### JavaScript SDK Repository: `ciresnave/authframework-js`

```
authframework-js/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── src/
│   ├── auth/
│   ├── admin/
│   ├── tokens/
│   ├── types/
│   ├── errors/
│   ├── utils/
│   └── index.ts
├── dist/
├── tests/
├── examples/
├── docs/
├── package.json
├── tsconfig.json
├── rollup.config.js
├── jest.config.js
├── README.md
├── LICENSE
├── CHANGELOG.md
└── CONTRIBUTING.md
```

## Migration Steps

### 1. Create New Repositories

```bash
# Create Python SDK repository
gh repo create ciresnave/authframework-python --public --description "Official Python SDK for AuthFramework"

# Create JavaScript SDK repository  
gh repo create ciresnave/authframework-js --public --description "Official JavaScript/TypeScript SDK for AuthFramework"
```

### 2. Prepare Python SDK

```bash
# Navigate to Python SDK directory
cd /path/to/AuthFramework/sdks/python

# Initialize git repository
git init
git add .
git commit -m "feat: initial Python SDK repository setup"

# Add remote and push
git remote add origin https://github.com/ciresnave/authframework-python.git
git branch -M main
git push -u origin main
```

### 3. Prepare JavaScript SDK

```bash
# Navigate to JavaScript SDK directory
cd /path/to/AuthFramework/sdks/javascript

# Initialize git repository
git init
git add .
git commit -m "feat: initial JavaScript SDK repository setup"

# Add remote and push
git remote add origin https://github.com/ciresnave/authframework-js.git
git branch -M main
git push -u origin main
```

### 4. Update Package Registries

#### Python SDK (PyPI)
- Package name: `authframework`
- Repository: `https://github.com/ciresnave/authframework-python`
- Update `pyproject.toml` URLs
- Configure GitHub Actions for PyPI publishing

#### JavaScript SDK (npm)
- Package name: `@authframework/js-sdk`
- Repository: `https://github.com/ciresnave/authframework-js`
- Update `package.json` URLs
- Configure GitHub Actions for npm publishing

### 5. GitHub Repository Settings

#### Python SDK Repository Settings
- **Secrets**: Add `PYPI_API_TOKEN` for automated publishing
- **Branch Protection**: Require PR reviews for main branch
- **Issues**: Enable with templates
- **Discussions**: Enable for community support
- **Wiki**: Enable for extended documentation
- **Topics**: `python`, `sdk`, `authentication`, `authorization`, `jwt`

#### JavaScript SDK Repository Settings
- **Secrets**: Add `NPM_TOKEN` for automated publishing
- **Branch Protection**: Require PR reviews for main branch
- **Issues**: Enable with templates
- **Discussions**: Enable for community support
- **Wiki**: Enable for extended documentation
- **Topics**: `javascript`, `typescript`, `sdk`, `authentication`, `authorization`, `jwt`

### 6. Documentation Updates

#### Update Main Repository README
Remove SDK documentation and add links to new repositories:

```markdown
## SDKs

AuthFramework provides official SDKs for multiple programming languages:

- **Python**: [authframework/authframework-python](https://github.com/ciresnave/authframework-python)
- **JavaScript/TypeScript**: [authframework/authframework-js](https://github.com/ciresnave/authframework-js)
```

#### Update SDK Documentation
- Create comprehensive README files for each SDK
- Set up documentation websites (ReadTheDocs for Python, GitHub Pages for JS)
- Update API documentation links
- Create migration guides for existing users

### 7. CI/CD Pipeline Setup

#### Python SDK Pipeline
- **Testing**: pytest with coverage on multiple Python versions (3.9-3.12)
- **Linting**: black, flake8, isort, mypy
- **Security**: bandit, safety
- **Publishing**: Automatic PyPI releases on git tags
- **Documentation**: Automatic docs building and deployment

#### JavaScript SDK Pipeline
- **Testing**: Jest with coverage on multiple Node.js versions (16, 18, 20)
- **Linting**: ESLint, Prettier
- **Type Checking**: TypeScript compiler
- **Building**: Rollup for ESM and CommonJS builds
- **Publishing**: Automatic npm releases on git tags
- **Documentation**: Automatic docs building and deployment

### 8. Migration Timeline

1. **Week 1**: Repository setup and basic file migration
2. **Week 2**: CI/CD pipeline configuration and testing
3. **Week 3**: Package registry setup and initial releases
4. **Week 4**: Documentation updates and community communication
5. **Ongoing**: Monitor for issues and gather feedback

## Benefits After Split

### For Users
- **Faster Setup**: Only download the SDK they need
- **Clear Documentation**: SDK-specific docs without monorepo complexity
- **Better Support**: Dedicated issue tracking per SDK
- **Framework Focus**: Each SDK optimized for its language ecosystem

### For Maintainers
- **Independent Releases**: SDK versions not tied to main project
- **Focused PRs**: Changes specific to each SDK
- **Specialized CI**: Testing pipelines optimized for each language
- **Clear Ownership**: Dedicated maintainers per SDK

### For the Main Project
- **Reduced Complexity**: Main repo focuses on core Rust implementation
- **Faster CI**: No need to test all SDKs on core changes
- **Modular Architecture**: Clear separation of concerns
- **Easier Onboarding**: New contributors can focus on specific areas

## Backwards Compatibility

### Existing Package Names
- Python: `authframework` package name remains the same
- JavaScript: `@authframework/js-sdk` package name remains the same

### Import Statements
No changes required in user code:

```python
# Python - remains the same
from authframework import AuthFrameworkClient
```

```javascript
// JavaScript - remains the same
import { AuthFrameworkClient } from '@authframework/js-sdk';
```

### Migration Communication
- Deprecation notices in old repository locations
- Clear migration guides in documentation
- Community announcements on GitHub Discussions
- Blog post explaining the benefits of the split

## Maintenance Strategy

### Ongoing Responsibilities
- **Core Team**: Maintain Rust implementation and coordinate SDK updates
- **Python Team**: Maintain Python SDK, respond to Python-specific issues
- **JavaScript Team**: Maintain JS SDK, respond to JS-specific issues
- **Community**: Contribute to all repositories based on expertise

### Coordination
- Regular sync meetings between SDK maintainers
- Shared issues for cross-SDK concerns
- Consistent API design across SDKs
- Coordinated security updates

This split provides a foundation for long-term sustainable development of the AuthFramework ecosystem while maintaining backwards compatibility and improving the developer experience.