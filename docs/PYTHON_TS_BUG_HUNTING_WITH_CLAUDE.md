# Bug Hunting for Python/TypeScript with Claude Code

## What's Relevant from Atlantis (and What's Not)

### Not Relevant for Managed Languages
- LLVM bitcode analysis
- Memory sanitizers (ASan, MSan, UBSan)
- Concolic execution with SymCC
- Buffer overflow / memory corruption detection
- C/C++ fuzzing infrastructure

### Highly Relevant Concepts
| Atlantis Technique | Python/TS Adaptation |
|--------------------|---------------------|
| Sinkpoint-centered approach | Trace data to dangerous APIs (SQL, subprocess, eval) |
| LLM taint analysis (MLLA) | Claude traces user input to dangerous sinks |
| Grammar inference | Generate valid API payloads, JSON structures |
| Static analysis integration | Semgrep, Bandit, ESLint security rules |
| Diff-focused analysis | Prioritize recently changed code |
| Iterative patch generation | Works identically |

---

## Part 1: Python/TypeScript Vulnerability Classes

### 1.1 Dangerous Sinks (The Sinkpoint Model)

**Python Sinks:**
```python
# Command Injection
os.system(user_input)
subprocess.run(user_input, shell=True)
subprocess.Popen(user_input, shell=True)

# SQL Injection
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
engine.execute(text(f"SELECT * FROM users WHERE id = {user_input}"))

# Code Injection
eval(user_input)
exec(user_input)
compile(user_input, '<string>', 'exec')

# Path Traversal
open(f"/data/{user_input}")
pathlib.Path(user_input).read_text()
shutil.copy(user_input, destination)

# Deserialization
pickle.loads(user_input)
yaml.load(user_input)  # without Loader=SafeLoader
marshal.loads(user_input)

# SSRF
requests.get(user_input)
urllib.request.urlopen(user_input)
httpx.get(user_input)

# Template Injection (SSTI)
jinja2.Template(user_input).render()
mako.template.Template(user_input).render()

# XXE
lxml.etree.parse(user_input)  # without proper flags
xml.etree.ElementTree.parse(user_input)
```

**TypeScript/JavaScript Sinks:**
```typescript
// Command Injection
child_process.exec(userInput)
child_process.spawn(userInput, { shell: true })

// SQL Injection (without parameterization)
db.query(`SELECT * FROM users WHERE id = ${userInput}`)
knex.raw(`SELECT * FROM users WHERE id = ${userInput}`)

// Code Injection
eval(userInput)
new Function(userInput)()
vm.runInContext(userInput)

// Path Traversal
fs.readFile(path.join('/data', userInput))
fs.createReadStream(userInput)

// Prototype Pollution
Object.assign(target, JSON.parse(userInput))
_.merge(target, userInput)
_.set(obj, userInput, value)

// XSS (in frontend or SSR)
element.innerHTML = userInput
dangerouslySetInnerHTML={{ __html: userInput }}

// SSRF
fetch(userInput)
axios.get(userInput)

// Regex DoS
new RegExp(userInput)  // with evil patterns
```

### 1.2 Non-Memory Bugs Unique to Dynamic Languages

| Bug Class | Description | Example |
|-----------|-------------|---------|
| **Type Confusion** | Wrong type passed, causes unexpected behavior | `user_id = request.args.get('id')` (string vs int) |
| **Auth Bypass** | Missing or broken authentication checks | Decorator missing, wrong comparison |
| **Authz Bypass** | User can access others' resources | IDOR, missing ownership check |
| **Mass Assignment** | Unvalidated fields updated | `User.update(**request.json)` |
| **Race Conditions** | TOCTOU, double-spend | Check-then-act without locking |
| **Logic Bugs** | Business logic flaws | Price manipulation, state machine bypass |
| **Secret Leakage** | Credentials in code/logs | Hardcoded API keys, debug logging |
| **Insecure Defaults** | Debug mode, weak crypto | `DEBUG=True` in prod, `md5` for passwords |

---

## Part 2: Claude-Powered Taint Analysis

### 2.1 The Core Approach (Adapted from MLLA)

Instead of complex symbolic execution, use Claude to trace data flow:

```
┌─────────────────────────────────────────────────────────┐
│                    TAINT ANALYSIS                       │
│                                                         │
│  1. Identify SOURCES (user input entry points)         │
│     - request.args, request.json, request.form         │
│     - sys.argv, input(), environment variables         │
│     - File reads, database results, API responses      │
│                                                         │
│  2. Identify SINKS (dangerous operations)              │
│     - See Section 1.1 above                            │
│                                                         │
│  3. Trace data flow from sources to sinks              │
│     - Follow variable assignments                       │
│     - Track through function calls                      │
│     - Note any sanitization/validation                  │
│                                                         │
│  4. Report if unsanitized data reaches sink            │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Practical Prompting Strategy

**System Prompt:**
```
You are a security analyst performing taint analysis on Python/TypeScript code.

Your task is to trace how user-controlled data flows through the application.

For each file/function you analyze:
1. Identify all SOURCES of user input
2. Identify all SINKS (dangerous operations)
3. Trace data flow paths from sources to sinks
4. Note any sanitization or validation along the path
5. Classify the finding: VULNERABLE, SAFE, or NEEDS_REVIEW

Be precise about variable names and line numbers.
```

**Analysis Prompt:**
```
Analyze this code for {vulnerability_type} vulnerabilities.

File: {file_path}
```python
{code}
```

For each potential vulnerability found, provide:
1. Source: Where does user input enter? (variable, line number)
2. Sink: Where is the dangerous operation? (function, line number)
3. Path: How does data flow from source to sink?
4. Sanitization: Is there any validation? Is it sufficient?
5. Verdict: VULNERABLE / SAFE / NEEDS_REVIEW
6. Confidence: HIGH / MEDIUM / LOW
7. Suggested Fix: How to remediate
```

### 2.3 Multi-File Analysis

For tracing across files (adapted from call graph analysis):

```
Step 1: Build a lightweight call graph
  - Find all function definitions
  - Find all function calls
  - Map imports to their sources

Step 2: For each source→sink candidate:
  - Follow the call chain
  - Track argument passing
  - Note where data transforms

Step 3: Report complete paths
  - "user input enters at api/routes.py:45"
  - "passed to services/user.py:get_user():23"
  - "reaches database.py:execute():78 unsanitized"
```

---

## Part 3: Integration with Static Analysis Tools

### 3.1 Tool → Claude Validation Pipeline

Static tools find candidates, Claude validates and explains:

```
┌────────────────┐     ┌─────────────────┐     ┌──────────────┐
│ Semgrep/Bandit │ ──▶ │ Claude Validates│ ──▶ │ Confirmed    │
│ (Fast, Noisy)  │     │ (Accurate)      │     │ Findings     │
└────────────────┘     └─────────────────┘     └──────────────┘
        │                      │
        │                      ▼
        │              ┌─────────────────┐
        │              │ False Positive  │
        │              │ Explanations    │
        │              └─────────────────┘
        ▼
┌────────────────┐
│ SARIF Report   │
│ with locations │
└────────────────┘
```

### 3.2 Recommended Tools

**Python:**
- **Semgrep**: Custom rules, good for injection patterns
- **Bandit**: Python-specific security linter
- **Safety**: Dependency vulnerability scanner
- **pip-audit**: Alternative dep scanner
- **Pylint** with security plugins

**TypeScript/JavaScript:**
- **Semgrep**: Works for TS/JS too
- **ESLint** with security plugins (eslint-plugin-security)
- **npm audit / yarn audit**: Dependency scanning
- **CodeQL**: GitHub's analysis (free for open source)

### 3.3 Claude Validation Prompt

```
A static analysis tool reported this potential vulnerability:

Rule: {rule_id}
Severity: {severity}
File: {file_path}
Line: {line_number}
Message: {tool_message}

Code context:
```{language}
{code_with_context}
```

Analyze this finding:
1. Is this a TRUE POSITIVE or FALSE POSITIVE?
2. If true positive:
   - What is the actual impact?
   - How could an attacker exploit this?
   - What is the recommended fix?
3. If false positive:
   - Why is the tool wrong?
   - What context did it miss?

Provide confidence level: HIGH / MEDIUM / LOW
```

---

## Part 4: Diff-Focused Security Review

### 4.1 The Approach (From Atlantis DiffAnalysisTask)

Focus on recently changed code - that's where new bugs are introduced:

```python
# Workflow
1. Get git diff (PR or recent commits)
2. Parse changed files and functions
3. For each change:
   a. Is this security-relevant? (touches auth, input handling, etc.)
   b. Does it introduce a new sink?
   c. Does it modify validation logic?
   d. Does it change access control?
4. Deep-dive on security-relevant changes
```

### 4.2 Change Classification

**High Priority (Always Review):**
- Authentication/authorization logic
- Input validation/sanitization
- Database queries
- File operations
- External API calls
- Cryptography usage
- Session/token handling

**Medium Priority:**
- New dependencies added
- Configuration changes
- Error handling changes
- Logging changes (secret leakage?)

**Low Priority:**
- UI/formatting changes
- Comments/documentation
- Test changes (unless removing tests)

### 4.3 Diff Analysis Prompt

```
Review this code change for security implications.

File: {file_path}
```diff
{diff_content}
```

Full file context (after change):
```{language}
{full_file}
```

Analyze:
1. What functionality changed?
2. Is this security-relevant? (auth, input handling, data access, etc.)
3. Does this change introduce any vulnerabilities?
4. Does this change FIX any vulnerabilities?
5. Are there any missing security considerations?

If vulnerabilities found, provide:
- Vulnerability type
- Exploitation scenario
- Recommended fix
```

---

## Part 5: Input Generation for Testing

### 5.1 Grammar-Aware API Testing (Adapted from Testlang)

For API endpoints, generate valid but malicious payloads:

```python
# Example: User registration endpoint
# POST /api/users
# Body: { "username": str, "email": str, "role": str }

# Claude generates test cases:
test_cases = [
    # SQL Injection in string fields
    {"username": "admin'--", "email": "test@test.com", "role": "user"},
    {"username": "test", "email": "test'@test.com", "role": "user"},

    # Mass Assignment (trying to set admin role)
    {"username": "test", "email": "test@test.com", "role": "admin"},
    {"username": "test", "email": "test@test.com", "role": "admin", "is_superuser": True},

    # Type Confusion
    {"username": ["array"], "email": "test@test.com", "role": "user"},
    {"username": {"nested": "object"}, "email": "test@test.com", "role": "user"},
    {"username": 12345, "email": "test@test.com", "role": "user"},

    # Path Traversal in string fields
    {"username": "../../../etc/passwd", "email": "test@test.com", "role": "user"},

    # XSS payloads
    {"username": "<script>alert(1)</script>", "email": "test@test.com", "role": "user"},

    # Boundary testing
    {"username": "", "email": "test@test.com", "role": "user"},
    {"username": "a" * 10000, "email": "test@test.com", "role": "user"},
]
```

### 5.2 Payload Generation Prompt

```
Generate security test payloads for this API endpoint.

Endpoint: {method} {path}
Request Schema:
```json
{schema}
```

Code handling this endpoint:
```{language}
{handler_code}
```

Generate test cases for:
1. SQL Injection (if database access)
2. Command Injection (if shell commands)
3. Path Traversal (if file operations)
4. XSS (if output rendered)
5. Mass Assignment (extra fields)
6. Type Confusion (wrong types)
7. Boundary Conditions (empty, huge, negative)
8. Authentication Bypass (if auth required)
9. Authorization Bypass (if ownership checks)

For each test case, provide:
- Payload (as JSON)
- What vulnerability it tests
- Expected vulnerable behavior
- Expected secure behavior
```

---

## Part 6: Iterative Bug Fixing

### 6.1 The Feedback Loop (From Atlantis Patch Generation)

```
┌──────────────────┐
│ Vulnerability    │
│ Report           │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Claude Generates │◀────────────────────┐
│ Fix              │                     │
└────────┬─────────┘                     │
         ▼                               │
┌──────────────────┐                     │
│ Apply Patch      │                     │
└────────┬─────────┘                     │
         ▼                               │
┌──────────────────┐     ┌───────────────┴──┐
│ Run Tests        │────▶│ Tests Fail?      │
└────────┬─────────┘     │ Provide error    │
         │               │ to Claude        │
         ▼               └──────────────────┘
┌──────────────────┐
│ Re-run Security  │
│ Analysis         │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Vulnerability    │
│ Fixed?           │
└──────────────────┘
```

### 6.2 Fix Generation Prompt

```
Fix this security vulnerability.

Vulnerability Type: {vuln_type}
File: {file_path}
Location: Line {line_number}

Vulnerable Code:
```{language}
{vulnerable_code}
```

Analysis:
{vulnerability_explanation}

Requirements:
1. Fix the vulnerability completely
2. Do not break existing functionality
3. Follow the codebase's existing patterns
4. Add input validation if missing
5. Use parameterized queries for SQL
6. Use safe APIs when available

{if previous_attempt_failed}
Previous fix attempt failed:
```{language}
{previous_fix}
```
Error: {error_message}

Try a different approach.
{/if}

Provide the complete fixed function/code block.
```

### 6.3 Common Fix Patterns

**SQL Injection → Parameterized Queries:**
```python
# Before (vulnerable)
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# After (fixed)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

**Command Injection → Avoid shell=True, use lists:**
```python
# Before (vulnerable)
subprocess.run(f"convert {input_file} {output_file}", shell=True)

# After (fixed)
subprocess.run(["convert", input_file, output_file], shell=False)
```

**Path Traversal → Validate and normalize:**
```python
# Before (vulnerable)
return open(f"/data/{filename}").read()

# After (fixed)
safe_path = Path("/data").resolve() / filename
if not safe_path.resolve().is_relative_to(Path("/data").resolve()):
    raise ValueError("Invalid path")
return safe_path.read_text()
```

---

## Part 7: Practical Claude Code Workflow

### 7.1 Single-Command Security Scan

```bash
# Conceptual workflow
claude "Perform a security review of this codebase focusing on:
1. Injection vulnerabilities (SQL, command, code)
2. Authentication/authorization issues
3. Sensitive data exposure
4. Insecure dependencies

Start with the API routes and trace inward.
Prioritize recently changed files (last 30 days).
For each finding, provide location, severity, and fix."
```

### 7.2 Recommended Workflow Steps

```
1. RECONNAISSANCE
   - Map the codebase structure
   - Identify entry points (API routes, CLI, etc.)
   - Find configuration and secrets
   - Check dependencies for known vulnerabilities

2. STATIC ANALYSIS
   - Run Semgrep/Bandit/ESLint with security rules
   - Collect findings with locations

3. TAINT ANALYSIS
   - For each entry point, trace user input
   - Identify all sinks in the codebase
   - Map paths from sources to sinks
   - Note sanitization along the way

4. VALIDATION
   - Review static analysis findings
   - Confirm or dismiss each one
   - Add context and exploitation scenarios

5. DIFF REVIEW
   - Focus on recent changes
   - Look for newly introduced issues
   - Check for security regressions

6. REMEDIATION
   - Generate fixes for confirmed issues
   - Validate fixes don't break tests
   - Re-run security analysis on fixed code
```

### 7.3 File-by-File vs Holistic Analysis

**File-by-File (Good for focused review):**
- Analyze one file at a time
- Good for smaller context
- May miss cross-file data flows

**Holistic (Better for auth/business logic):**
- Analyze related files together
- Better for understanding data flow
- Needed for auth/authz review
- Requires summarization for large codebases

### 7.4 Context Management for Large Codebases

```
Strategy: Hierarchical Summarization

1. First pass: Summarize each file
   - What does it do?
   - What are the entry points?
   - What dangerous operations?

2. Build a map:
   - Routes → Handlers → Services → Database
   - Authentication flow
   - Authorization checkpoints

3. Deep dive:
   - Use summaries to identify high-risk areas
   - Analyze those files in detail
   - Trace specific data flows
```

---

## Part 8: Integration Points

### 8.1 Git Hooks (Pre-commit Security Check)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: security-check
        name: Claude Security Review
        entry: claude-security-check  # Your script
        language: system
        types: [python, typescript]
        stages: [commit]
```

### 8.2 CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Review
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get changed files
        id: changes
        run: |
          echo "files=$(git diff --name-only origin/main...HEAD | tr '\n' ' ')" >> $GITHUB_OUTPUT

      - name: Run Claude Security Review
        run: |
          claude "Review these changed files for security issues:
          ${{ steps.changes.outputs.files }}

          Focus on: injection, auth bypass, data exposure
          Output as GitHub annotations format"
```

### 8.3 IDE Integration

For VS Code, create a task:
```json
{
  "label": "Security Review Current File",
  "type": "shell",
  "command": "claude",
  "args": [
    "Review ${file} for security vulnerabilities. Focus on injection, auth issues, and data exposure."
  ]
}
```

---

## Part 9: Example Prompts Library

### 9.1 Quick Security Scan
```
Scan this Python/TypeScript codebase for security vulnerabilities.
Focus on the top 10 web application risks (OWASP).
For each finding, provide file:line, severity (HIGH/MEDIUM/LOW), and one-line description.
```

### 9.2 Authentication Review
```
Review the authentication implementation in this codebase:
1. How are users authenticated?
2. How are sessions/tokens managed?
3. Are there any bypass possibilities?
4. Is the password handling secure?
5. Are there any hardcoded credentials?
```

### 9.3 API Security Audit
```
Audit the API endpoints in this codebase:
1. List all endpoints with their auth requirements
2. Check for injection vulnerabilities in each
3. Verify authorization (can users access others' data?)
4. Check for rate limiting
5. Look for sensitive data exposure in responses
```

### 9.4 Dependency Review
```
Review the dependencies in package.json/requirements.txt:
1. Are any packages known to be vulnerable?
2. Are there unnecessary dependencies that increase attack surface?
3. Are dependency versions pinned?
4. Are there any typosquatting risks?
```

### 9.5 Secrets Scan
```
Scan this codebase for exposed secrets:
1. API keys and tokens
2. Database credentials
3. Private keys
4. JWT secrets
5. Third-party service credentials

Check: source files, config files, .env files, comments
```

---

## Summary: Key Techniques for Python/TS

| Technique | How It Works | When to Use |
|-----------|--------------|-------------|
| **Taint Analysis** | Trace user input to dangerous sinks | Always - core technique |
| **Static Tool + Claude** | Tools find candidates, Claude validates | Large codebases |
| **Diff-Focused Review** | Prioritize recently changed code | PR reviews, CI |
| **Grammar-Aware Fuzzing** | Generate valid but malicious API payloads | API testing |
| **Iterative Fixing** | Generate fix, test, refine | Remediation phase |
| **Dependency Scanning** | Check for known vulnerable packages | Regular maintenance |
| **Auth/Authz Review** | Trace authentication and access control | Sensitive applications |

The core insight from Atlantis that transfers well: **Use Claude's semantic understanding to do what static tools can't** - understand context, trace data flow across complex paths, and validate whether something is actually exploitable.
