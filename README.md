# Security Onion MCP Server

![Tests](https://github.com/Security-Onion-Solutions/securityonion-mcp/actions/workflows/tests.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)
![Version](https://img.shields.io/badge/version-1.0.0-blue)

This project contains the backend server for the Security Onion Model Context Protocol (MCP).

## Prerequisites

*   Python 3.12+
*   Access to set environment variables

## Environment Variables

The server uses the following environment variables:

* `SO_CLIENT_ID`: Your Security Onion client ID
* `SO_CLIENT_SECRET`: Your Security Onion client secret
* `SO_API_ENDPOINT`: The URL of your Security Onion manager (e.g., https://yourmanager)
* `SO_API_VERIFY_SSL`: Set to "false" to disable SSL verification (useful for self-signed certificates)
* `SO_ENABLE_FILE_LOGGING`: Set to "true" to enable file logging to securityonion-mcp.log (disabled by default)

## Setup and Running

### Linux / macOS

1.  **Install Modules:**
    Navigate to the project directory in your terminal and execute:
    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
    This will install the needed python modules

### Windows

1.  **Install Modules:**
    Navigate to the project directory in your command prompt and execute:
    ```cmd
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    ```
    This will install the needed python modules

## Setup for Roo Code

### Linux / macOS Configuration

```json
{
  "mcpServers": {
    "securityonion": {
      "command": "/home/user/Projects/securityonion-mcp/venv/bin/python",
      "args": [
        "/home/user/Projects/securityonion-mcp/security_onion_server.py"
      ],
      "workingDirectory": "/home/user/Projects/securityonion-mcp",
      "env": {
        "SO_CLIENT_ID": "YOURCLIENT",
        "SO_CLIENT_SECRET": "YOURSECRET",
        "SO_API_ENDPOINT": "https://yourmanager",
        "SO_API_VERIFY_SSL": "false",
        "SO_ENABLE_FILE_LOGGING": "false"
      },
      "syncTimeout": 10000,
      "type": "stdio",
      "alwaysAllow": [
        "ping",
        "query_alerts"
      ],
      "disabled": true
    }
  }
}
```

### Windows Configuration

```json
{
  "mcpServers": {
    "securityonion": {
      "command": "C:\\Users\\user\\Projects\\securityonion-mcp\\venv\\Scripts\\python.exe",
      "args": [
        "C:\\Users\\user\\Projects\\securityonion-mcp\\security_onion_server.py"
      ],
      "workingDirectory": "C:\\Users\\user\\Projects\\securityonion-mcp",
      "env": {
        "SO_CLIENT_ID": "YOURCLIENT",
        "SO_CLIENT_SECRET": "YOURSECRET",
        "SO_API_ENDPOINT": "https://yourmanager",
        "SO_API_VERIFY_SSL": "false",
        "SO_ENABLE_FILE_LOGGING": "false"
      },
      "syncTimeout": 10000,
      "type": "stdio",
      "alwaysAllow": [
        "ping",
        "query_alerts"
      ],
      "disabled": true
    }
  }
}
```

## Integration with Claude Desktop

### macOS Configuration
```json
{
  "mcpServers": {
    "securityonion": {
      "command": "/Users/user/Projects/securityonion-mcp/venv/bin/python",
      "args": ["/Users/user/Projects/securityonion-mcp/security_onion_server.py"],
      "env": {
        "SO_CLIENT_ID": "YOURCLIENT",
        "SO_CLIENT_SECRET": "YOURSECRET",
        "SO_API_ENDPOINT": "https://yourmanager",
        "SO_API_VERIFY_SSL": "false",
        "SO_ENABLE_FILE_LOGGING": "false"
      }
    }
  }
}
```

### Windows Configuration
```json
{
  "mcpServers": {
    "securityonion": {
      "command": "C:\\Users\\user\\Projects\\securityonion-mcp\\venv\\Scripts\\python.exe",
      "args": ["C:\\Users\\user\\Projects\\securityonion-mcp\\security_onion_server.py"],
      "env": {
        "SO_CLIENT_ID": "YOURCLIENT",
        "SO_CLIENT_SECRET": "YOURSECRET",
        "SO_API_ENDPOINT": "https://yourmanager",
        "SO_API_VERIFY_SSL": "false",
        "SO_ENABLE_FILE_LOGGING": "false"
      }
    }
  }
}
```


This server communicates using the Model Context Protocol (MCP) over standard input/output (stdio), not via a network port. To use it with clients like Claude Desktop or Cline/Roo:

1.  **Ensure Prerequisites:** Make sure Python 3.8+ is installed and accessible in the system's PATH, and that any required environment variables for `security_onion_server.py` are set appropriately for the environment where the client will launch the script.
2.  **Configure Client:** Configure your Claude Desktop or Cline/Roo instance to launch this server as a command-line process.
    *   Use the appropriate configuration above for your operating system and access method
    *   Ensure paths in the configuration match your actual installation directory



## LLM Rules Integration

The project includes an `LLMRULES.md` file that contains a condensed reference for Onion Query Language (OQL). This file helps LLMs (Large Language Models) understand how to properly formulate OQL queries when interacting with the Security Onion MCP Server.

### Integration with VSCode

To use these rules with Roo in VSCode:

1. **Copy the rules to a special file:**
   ```bash
   cp LLMRULES.md .roorules
   ```
   or
   ```bash
   cp LLMRULES.md .clinerules
   ```

2. **Verify the rules are loaded:**
   When you start a conversation with Roo in VSCode, it will automatically load the rules from these files.

### Integration with Claude Desktop

To use these rules with Claude Desktop:

1. **Create a dedicated Security Onion query project:**
   It's recommended to create a specific project in Claude Desktop dedicated to querying Security Onion:
   
   - Open Claude Desktop
   - Click the "+" button in the top-right corner
   - Select "Use a project"
   - Click "Create new project"
   - Name it "Security Onion Queries" or similar
   - Click "Create project"

2. **Add the LLMRULES.md file to your project knowledge:**
   - In your new project, click on the "Project" tab in the sidebar
   - Click on "Project knowledge"
   - Click "Add files" or drag and drop the LLMRULES.md file
   - This permanently adds the file to your project knowledge, making it available in all conversations within this project

3. **Use the project for all Security Onion queries:**
   Return to this project whenever you need to query Security Onion. The LLMRULES.md file will always be available in the project knowledge, so you don't need to upload it for each new conversation.

## Event Payload Filtering

The Security Onion MCP Server filters event payloads to reduce context size when returning query results. This is important for:

1. **Reducing Token Usage:** By filtering out unnecessary fields, the server reduces the amount of data sent to LLM models, which helps optimize token usage and costs.

2. **Focusing on Relevant Data:** The filtering ensures that only the most relevant security event fields are included in responses, making it easier for models to analyze and respond to security events.

### Default Fields

The server includes a predefined set of default fields in `so_modules/config.py`. These fields are used to filter event payloads to include only the most relevant security information.

To see the current list of default fields, please refer to the `DEFAULT_FIELDS` set in the `so_modules/config.py` file.

### Customizing Fields

To add additional fields to the filtering:

1. Open `so_modules/config.py`
2. Locate the `DEFAULT_FIELDS` set
3. Add your desired fields to the set
4. Restart the server for changes to take effect

For example, to add a new field:

```python
DEFAULT_FIELDS = {
    # Existing fields are already defined in the set
    "your.new.field"  # Add your custom field here
}
```

Note that some fields like `user.name` and `process.name` are already included in the default set. Always check the current contents of `DEFAULT_FIELDS` in `so_modules/config.py` before adding new fields to avoid duplication.

## Testing

The Security Onion MCP project maintains 100% test coverage to ensure code quality and reliability. This section provides comprehensive information about running tests for the project.

### Test Environment Setup

Before running tests, you need to set up the test environment:

1. **Create and Activate Virtual Environment:**
   ```bash
   # Linux/macOS
   python -m venv venv
   source venv/bin/activate

   # Windows
   python -m venv venv
   venv\Scripts\activate
   ```

2. **Install Test Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   This installs all required dependencies, including pytest, pytest-mock, pytest-asyncio, pytest-cov, and pytest-env.

### Running Tests

#### Basic Test Execution

To run all tests without coverage reporting:

```bash
python -m pytest
```

#### Running Tests with Coverage

To run tests with coverage reporting:

```bash
# Run tests with coverage for the entire project
source venv/bin/activate && python -m pytest --cov=. --cov-report=term-missing
```

This command:
- Activates the virtual environment
- Runs all tests
- Generates coverage for the entire project (excluding venv, site-packages, and tests)
- Displays a terminal report showing which lines are missing coverage

#### Coverage Report Options

The project supports various coverage report formats:

1. **Terminal Report:**
   ```bash
   python -m pytest --cov=. --cov-report=term
   ```

2. **Terminal Report with Missing Lines:**
   ```bash
   python -m pytest --cov=. --cov-report=term-missing
   ```

3. **HTML Coverage Report:**
   ```bash
   python -m pytest --cov=. --cov-report=html
   ```
   This generates an HTML report in the `htmlcov` directory. Open `htmlcov/index.html` in a browser to view the detailed coverage report.

4. **XML Coverage Report:**
   ```bash
   python -m pytest --cov=. --cov-report=xml
   ```
   This generates an XML report in `coverage.xml`, which can be used with CI/CD tools.

### Current Coverage Status

The project currently maintains **100% test coverage** across all modules. This complete coverage ensures that all code paths are tested and verified to work as expected.

### Test Structure and Organization

The tests are organized in the `tests` directory with the following structure:

- **Module-specific tests:** Files named `test_<module_name>.py` contain tests for specific modules (e.g., `test_api.py`, `test_config.py`)
- **Coverage-specific tests:** Files named `test_<module_name>_coverage.py` contain additional tests to ensure complete coverage
- **Integration tests:** Tests that verify the integration between different components
- **Fixtures and configuration:** `conftest.py` contains pytest fixtures and shared test utilities

The test configuration is defined in `pytest.ini`, which specifies:
- Test discovery patterns
- Coverage configuration
- Exclusion patterns for coverage reporting

### Prerequisites for Testing

To run the tests, you need:

1. Python 3.8 or higher
2. All dependencies listed in requirements.txt
3. A clean environment (tests are designed to run in isolation without external dependencies)

The test suite is designed to be self-contained and does not require an active connection to a Security Onion instance.