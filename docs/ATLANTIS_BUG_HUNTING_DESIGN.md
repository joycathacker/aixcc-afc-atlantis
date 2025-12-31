# Atlantis CRS: Bug Hunting Techniques Design Document

## Executive Summary

Atlantis is Team Atlanta's Cyber Reasoning System (CRS) for the AIxCC competition. This document focuses exclusively on the **bug hunting techniques** used by the system, excluding competition infrastructure (APIs, Kubernetes, Docker orchestration, etc.).

The system employs a **multi-strategy hybrid approach** combining:
1. **Coverage-guided fuzzing** (AFL++, LibFuzzer, Jazzer)
2. **Symbolic/Concolic execution** (SymCC, Z3 constraint solving)
3. **Grammar-based input generation** (Testlang)
4. **LLM-powered analysis and generation** (MLLA, DeepGen, ExpKit)
5. **Static analysis for guidance** (CodeQL, Joern, SVF)
6. **LLM-based patch generation** (Multiple agent architectures)

---

## Part 1: Core Bug Hunting Philosophy

### 1.1 The Sinkpoint-Centered Model

The system views vulnerability discovery as a **two-phase problem**:

1. **Sinkpoint Reaching**: Getting attacker-controlled input to reach dangerous code locations (SQL queries, system calls, memory operations, etc.)

2. **Sinkpoint Exploitation**: Crafting inputs that trigger actual vulnerabilities at those locations

This model is explicitly implemented in the Java CRS but conceptually underlies the entire system. The key insight is that **crash location ≠ bug location** - the code that crashes may be far from the actual vulnerability.

### 1.2 Multi-Strategy Parallelism

Rather than relying on a single technique, Atlantis runs **multiple complementary strategies in parallel**:

| Strategy | Strength | Weakness |
|----------|----------|----------|
| Coverage-guided fuzzing | Fast, finds shallow bugs | Struggles with complex constraints |
| Concolic execution | Solves path constraints systematically | Timeout/scalability issues |
| Grammar-based generation | Syntactically valid inputs | Requires grammar inference |
| LLM analysis | Semantic understanding | Expensive, slower |
| Directed fuzzing | Targets specific code | Needs reachability info |

The system dynamically allocates resources based on which strategies are making progress.

### 1.3 Feedback Loop Architecture

All strategies feed into a shared **corpus** and **coverage database**:

```
Strategy A → generates inputs → Executor → coverage/crashes
Strategy B → generates inputs ↗              ↓
Strategy C → generates inputs ↗         Corpus DB
                                             ↓
                                    All strategies can use
                                    successful inputs from others
```

---

## Part 2: Fuzzing Infrastructure (UniAFL)

### 2.1 Multi-Stage Analyzer (MSA)

The core fuzzing engine executes strategies in a **cyclic pipeline**:

```
TestStage → ConcolicStage → TestLangStage → DictStage →
GivenFuzzerStage → MLLAStage → SeedShareStage → (repeat)
```

Each stage:
1. Generates new inputs using its strategy
2. Executes inputs and collects coverage
3. Adds interesting inputs to shared corpus
4. Passes control to next stage

### 2.2 Weighted Corpus Scheduling

The scheduler prioritizes seeds based on:

```
Score(seed) = Base(1)
            + DiffFileWeight(2) × modified_files_covered
            + DiffLineWeight(4) × modified_lines_covered
            + KeyWeight(4) × key_function_matches
            + VulnWeight(8) × vulnerability_function_matches
```

Seeds covering recently modified code (diffs) or known vulnerable patterns get higher priority. The scheduler uses **weighted random selection** for corpus sampling.

### 2.3 Crash Handling

When a crash is detected:
1. Capture sanitizer output (ASan, MSan, UBSan)
2. Symbolize stack trace using LLVM symbolizer
3. Deduplicate by BLAKE2B hash of crash input
4. Extract vulnerability type from sanitizer message
5. Generate SARIF report for the finding

---

## Part 3: Concolic Execution

### 3.1 Constraint-Based Path Exploration

Concolic execution combines **concrete execution** with **symbolic analysis**:

```
Input → SymCC (Instrumented Binary)
         ↓
    Path Constraints Collected
    (e.g., input[0]=='P' ∧ input[1]=='N' ∧ input[2]=='G')
         ↓
    Negate one constraint to explore new path
    (e.g., input[0]!='P')
         ↓
    Z3 SMT Solver finds satisfying assignment
         ↓
    New input generated → feeds back to fuzzer
```

### 3.2 Solver Configuration

- **Timeout**: 30 seconds per constraint (prevents explosion)
- **Depth limit**: Tracks constraint depth to avoid infinite loops
- **Solution caching**: Avoids re-solving identical constraints
- **Optimistic mode**: Relaxes constraints if normal solving fails

### 3.3 Path Constraint Transformations

Before solving, constraints are optimized:
1. **Length inference**: Add `len(input) >= N` constraints
2. **Loop reduction**: Simplify loop-induced constraint patterns
3. **Expression optimization**: Simplify boolean expressions

---

## Part 4: Grammar-Based Generation (Testlang)

### 4.1 Grammar Representation

Testlang is a domain-specific language for input grammars:

```json
{
  "default_endian": "little",
  "records": {
    "INPUT": {
      "byte_size": 1024,
      "fields": {
        "magic": {"kind": "bytes", "byte_size": 4, "possible_values": ["PNG\0"]},
        "version": {"kind": "int", "byte_size": 4, "min": 1, "max": 100},
        "data_length": {"kind": "int", "byte_size": 4},
        "data": {"kind": "bytes", "byte_size": {"depends_on": "data_length"}}
      }
    }
  }
}
```

Features:
- **Type system**: int, string, bytes, float, union, array
- **Size dependencies**: Fields whose size depends on other fields
- **Value constraints**: min/max, possible values, terminators
- **Endianness**: Per-field big/little endian

### 4.2 Grammar Inference via LLM

The **Reverser** module infers grammars from harness code:

1. Extract harness source and target library code
2. Build code property graph using Joern
3. Identify input parsing patterns
4. Ask LLM: "Analyze this code and describe the expected input format"
5. Convert LLM response to Testlang schema

**Prompt pattern**:
```
Given this fuzzer harness code:
[CODE]

And these library functions it calls:
[LIBRARY CODE]

Describe the expected input format including:
- Magic bytes or headers
- Length fields and their locations
- Data structures and their layouts
- Any constraints on field values
```

### 4.3 Grammar-Aware Mutation

Once a grammar is known, mutations preserve validity:

| Mutator Type | Operation |
|--------------|-----------|
| Field mutators | bit_flip, byte_add, byte_rand (26 variants) |
| Array mutators | Insert/remove elements |
| Union mutators | Switch between union variants |
| Record mutators | Insert/replace valid sub-records |

Example: Instead of randomly flipping bytes in a PNG file, the mutator knows to:
- Keep magic bytes intact
- Modify length fields consistently with data
- Generate valid chunk types

---

## Part 5: Dictionary-Based Generation

### 5.1 Token Extraction

The **DictGen** module learns function-specific tokens:

**For C/C++** (LLM-based):
```
Prompt: "What string constants, magic bytes, and format specifiers
         appear in this function? List them as fuzzing dictionary entries."

Function: parse_config(char* data, size_t len)
...code...

Response: "CONFIG_", "version=", "\n", "true", "false", "0x"
```

**For Java** (Static analysis):
```python
def extract_constants(java_file):
    # Find imported classes
    # Extract static final fields
    # Return {name: (value, line_number)}
```

### 5.2 Dictionary Application

Dictionary tokens are inserted at random positions:

```
Original input: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
Dictionary: ["PNG", 0xDEADBEEF, "config"]
                    ↓
Mutated: [0x00, "PNG", 0x03, 0x04, 0x05]  // Insert at offset 1
```

A mutation tracker prevents duplicate mutations using hash tables.

---

## Part 6: LLM-Powered Bug Hunting (MLLA)

### 6.1 Multi-Agent Architecture

MLLA (Multi-Language LLM Agent) uses a **LangGraph state machine**:

```
                    ┌─────────────────┐
                    │  Preprocessor   │
                    │ (Extract CGs,   │
                    │  find sinks)    │
                    └────────┬────────┘
                             ↓
                    ┌─────────────────┐
                    │ CPUnderstand    │
                    │ Agent           │
                    │ (Analyze code)  │
                    └────────┬────────┘
                             ↓
                    ┌─────────────────┐
                    │ BugCandDetect   │
                    │ Agent (BCDA)    │
                    │ (Find vulns)    │
                    └────────┬────────┘
                             ↓
                    ┌─────────────────┐
                    │ Orchestrator    │
                    │ (Generate PoVs) │
                    └────────┬────────┘
                             ↓
                    ┌─────────────────┐
                    │ Execute & Test  │
                    └─────────────────┘
```

### 6.2 Taint Analysis Agent

The BCDA (Bug Candidate Detection Agent) performs LLM-guided taint analysis:

```python
class TaintAnalysisState:
    paths: List[str]                # Paths to vulnerability
    input_sources: List[str]        # Entry points (stdin, files)
    vuln_sink_functions: List[str]  # Dangerous functions
```

**Prompt pattern**:
```
Analyze this code for potential vulnerabilities.

Entry point: LLVMFuzzerTestOneInput(data, size)
Sink functions: [memcpy, strcpy, sprintf, system]

Trace how input data flows from entry to these sinks.
Identify any paths where attacker-controlled data reaches
a sink without proper validation.

For each vulnerability found:
1. Describe the data flow path
2. Explain what input would trigger the bug
3. Classify the vulnerability type (buffer overflow, injection, etc.)
```

### 6.3 PoV Generation

Once vulnerabilities are identified, the **BlobGen Agent** generates proof-of-vulnerability inputs:

```python
def generate_pov(vulnerability_info):
    prompt = f"""
    Generate a Python script that creates an input triggering this vulnerability:

    Vulnerability: {vulnerability_info.type}
    Location: {vulnerability_info.file}:{vulnerability_info.line}
    Data flow: {vulnerability_info.path}

    The script should:
    1. Create bytes that reach the vulnerable code
    2. Trigger the specific vulnerability condition
    3. Output the bytes to stdout
    """

    llm_response = call_llm(prompt)
    python_code = extract_code(llm_response)

    # Execute in sandbox
    pov_bytes = execute_safely(python_code)
    return pov_bytes
```

---

## Part 7: DeepGen (LLM Test Generation Service)

### 7.1 Task Types

DeepGen runs three complementary tasks:

| Task | Purpose |
|------|---------|
| **OneShotTask** | Generate random test cases from code understanding |
| **DiffAnalysisTask** | Focus on recently changed code |
| **DiffSummaryAnalyzer** | Use reachability summaries to guide generation |

### 7.2 Script Evolution

Successful generation scripts are **evolved** using LLM:

```python
async def deep_evolve_async(engine, script, summary):
    """Evolve a successful script to generate more variants"""
    prompt = f"""
    This Python script successfully generated test inputs:
    {script}

    It achieved this coverage: {summary}

    Modify the script to:
    1. Generate different but related inputs
    2. Target uncovered code paths
    3. Try edge cases and boundary conditions
    """

    evolved_script = await llm.generate(prompt)
    return evolved_script
```

### 7.3 Seed Distribution

Generated seeds flow through a **shared memory buffer**:

```
DeepGen Workers → ZMQ DEALER → Circular Buffer (100MB)
                                      ↓
                              Seed Ensembler (validates)
                                      ↓
                              CRASH → Submit to VAPI
                              COVERAGE → Distribute to fuzzers
                              DISCARD → Drop
```

---

## Part 8: Directed Fuzzing (Bullseye)

### 8.1 Target-Directed Approach

Bullseye uses **LLVM bitcode analysis** to direct fuzzing toward specific code:

```
Target: vulnerable_function() at file.c:line:123
         ↓
Analyze LLVM bitcode
         ↓
Compute distance from each basic block to target
         ↓
Instrument binary with distance feedback
         ↓
AFL++ mutation favors inputs closer to target
```

### 8.2 Distance Computation

```
Distance(block) = min(edges to reach target function)
                + intra-function distance to target line
```

The fuzzer preferentially mutates seeds with **lower distance** to the target.

### 8.3 Configuration

```bash
BULLSEYE_TARGET_LOC="file.c:123"        # Target location
BULLSEYE_BC_FILE="harness.bc"            # LLVM bitcode
BULLSEYE_CONTEXT_MAX_DEPTH=5             # Callstack depth
BULLSEYE_SANITIZER="address"             # ASan/MSan/UBSan
```

---

## Part 9: Java-Specific Techniques

### 9.1 Sinkpoint Management

Java CRS explicitly tracks **sinkpoints** (dangerous code locations):

```python
class Sinkpoint:
    coord: InsnCoordinate      # Bytecode location
    type: Set[str]             # Vuln types (SQLi, LDAPi, etc.)
    in_diff: bool              # In recently changed code?
    beepseeds: Set[BeepSeed]   # Inputs that reach this point
    crashes: Set[Crash]        # Successful exploits
```

### 9.2 Beepseed Collection

Jazzer is instrumented with **CodeMarker** to record when marked locations are hit:

```java
// Instrumented at compile time
if (CodeMarker.isMarked(currentLocation)) {
    CodeMarker.recordBeepseed(input, currentLocation, stackTrace);
}
```

Output: JSON files containing input + execution context for each sinkpoint hit.

### 9.3 LLM-POC-Gen

For Java vulnerabilities, LLM generates exploitation payloads:

**Vulnerability Descriptions** (from prompt templates):
```
SQL Injection: Create inputs that cause SQL syntax errors
LDAP Injection: Invalid LDAP search filter syntax
Command Injection: Inputs that invoke 'jazze' command
SSRF: Access external URLs
Path Traversal: Access 'jazzer-traversal' file
Deserialization: Trigger gadget chains
```

**Prompt Structure**:
```
[Code Context - files from stack trace]

[Vulnerability Description]
The code is potentially vulnerable to {vuln_type}.
Inputs that cause {trigger_condition} will be detected.
Common payloads: {examples}

[Stack Trace Context]
{recent_execution}

[Task]
Generate a hexadecimal input string that triggers
the vulnerability at {location}.
```

---

## Part 10: Static Analysis Integration

### 10.1 Call Graph Construction

Multiple tools build complementary call graphs:

| Tool | Language | Strength |
|------|----------|----------|
| **CodeQL** | C/C++, Java | Precise, handles templates |
| **Joern** | C/C++, Java | Property graphs, flexible queries |
| **SVF** | C/C++ | Pointer alias analysis |
| **Sootup** | Java | Class hierarchy analysis |

### 10.2 Reachability Analysis

Two-phase hybrid approach:

**Phase 1: Static Taint Analysis (STA)**
```scala
// Joern query
def entry = cpg.method.nameExact("fuzzerTestOneInput")
def src = entry.parameter
def sink = cpg.method.nameExact("vulnerable_function")
sink.reachableByFlows(src)  // Find data flow paths
```

**Phase 2: Call Graph Analysis (CG)**
When STA fails (indirect calls, polymorphism):
```python
def find_path(source, sink, callgraph):
    # BFS from source methods
    source_reachable = bfs_forward(source)
    # BFS from sink methods (reversed)
    sink_reachable = bfs_backward(sink)
    # Intersection = path exists
    return source_reachable & sink_reachable
```

### 10.3 Feeding into Fuzzing

Static analysis results guide fuzzing:

1. **Distance maps**: Methods → distance to vulnerability
2. **Reachability info**: Which harnesses can reach which sinks
3. **Sinkpoint priorities**: Focus on reachable vulnerabilities first

---

## Part 11: LLM-Based Patch Generation

### 11.1 Agent Architectures

The system uses **11+ different agent architectures** in parallel:

| Agent | Approach |
|-------|----------|
| **Martian** | ReACT-based fault localization → minimal patching |
| **ClaudeLike** | Iterative refinement with failure feedback |
| **Vincent** | Complex state machine with property analysis |
| **SWE-Agent** | Full SWE-Agent framework with tool use |
| **Aider** | Aider coder with reflection |
| **PRISM** | Multi-team orchestration (3 teams + supervisor) |
| **MultiRetrieval** | System-guided with backup LLM |

### 11.2 Fault Localization

Before patching, the system localizes the bug:

**CodeRoverK (Interactive)**:
```
System: You are analyzing a bug. The crash location is NOT necessarily
        the bug location. Use code inspection tools to find the actual bug.

Available tools:
- view_file(path, start_line, end_line)
- search_code(pattern)
- get_function_definition(name)

Task: Find the root cause of this crash:
{crash_log}
{sanitizer_output}
```

**Agentless (Log Analysis)**:
- Parse sanitizer output for error type
- Extract relevant stack frames
- Identify candidate functions

### 11.3 Patch Generation Prompts

**Core prompt structure**:
```
Generate a patch for function {function_name} in {file_path}.

## Bug Analysis
{analysis_from_fault_localization}

## Rules
- Do not change function signatures
- Do not assume unseen macros/functions
- Do not use fuzzer-specific code
- Do not remove sanitizer-guarded assertions

## Previous Failed Attempts (if any)
{failed_patches_with_explanations}

## Output Format
```diff
--- a/path/to/file.c
+++ b/path/to/file.c
@@ -10,5 +10,6 @@
 context line
-removed line
+added line
 context line
```
```

### 11.4 Patch Validation Pipeline

```
Patch Application
    ↓ (success?)
Compilation Check
    ↓ (compiles?)
PoV Execution
    ↓ (bug fixed?)
Functional Tests
    ↓ (tests pass?)
SUCCESS → Submit patch
```

Failed patches feed back into the LLM with explanations:
- Compilation error: stderr output
- PoV still triggers: crash log
- Tests fail: test output

---

## Part 12: Key Algorithms Summary

### 12.1 Weighted Seed Scheduling
```python
def select_seed(corpus, weights):
    total = sum(weights.values())
    r = random.random() * total
    cumulative = 0
    for seed, weight in weights.items():
        cumulative += weight
        if r <= cumulative:
            return seed
```

### 12.2 Constraint Negation
```python
def generate_new_path(path_constraints):
    for i, constraint in enumerate(path_constraints):
        # Try negating this constraint
        new_constraints = path_constraints[:i] + [NOT(constraint)]
        solution = z3_solve(new_constraints, timeout=30)
        if solution:
            return solution.to_input()
    return None
```

### 12.3 Grammar-Valid Mutation
```python
def mutate_valid(input_bytes, grammar):
    ast = parse(input_bytes, grammar)
    field = random.choice(ast.fields)

    if field.type == "int":
        field.value = mutate_int(field.value, field.constraints)
    elif field.type == "bytes":
        field.value = mutate_bytes(field.value, field.constraints)
    # ... other types

    return serialize(ast, grammar)
```

### 12.4 LLM Code Generation
```python
def generate_pov_with_llm(vuln_info, code_context):
    messages = [
        {"role": "system", "content": SECURITY_ANALYST_PROMPT},
        {"role": "user", "content": format_vuln_prompt(vuln_info, code_context)}
    ]

    response = llm.chat(messages, temperature=0.7)
    code = extract_python_code(response)

    # Execute in sandbox
    result = sandbox_execute(code, timeout=30)
    return result.stdout  # The PoV bytes
```

---

## Part 13: Ideas for Lightweight Claude Code Version

### 13.1 Core Capabilities to Replicate

A lightweight version could focus on:

1. **LLM-guided vulnerability analysis** (MLLA-style)
   - Analyze code for vulnerability patterns
   - Trace data flow from input to dangerous operations
   - Generate candidate PoV inputs

2. **Iterative patch generation** (ClaudeLike-style)
   - Fault localization via code analysis
   - Generate patches with feedback loop
   - Validate patches locally

3. **Grammar inference** (Testlang-style)
   - Analyze code to understand input format
   - Generate structurally valid test inputs

### 13.2 Simplified Architecture

```
User provides: Source code + known vulnerability info
                         ↓
Claude Code analyzes code structure
                         ↓
Identifies input parsing patterns
                         ↓
Generates test inputs (grammar-aware)
                         ↓
Runs tests, collects crashes
                         ↓
For crashes: Generate patches
                         ↓
Validate patches (compile + test)
```

### 13.3 Key Prompting Patterns to Reuse

**Vulnerability Analysis**:
```
Analyze this code for {vulnerability_type} vulnerabilities.
Trace how user input reaches dangerous operations.
For each finding, explain:
1. The data flow path
2. What input triggers the bug
3. How to fix it
```

**Grammar Inference**:
```
This function parses input data. Describe the expected format:
- Header/magic bytes
- Length fields
- Data structures
- Constraints
```

**Patch Generation**:
```
Fix this vulnerability without changing the API.
Previous attempt failed because: {error}
Try a different approach.
```

### 13.4 What Can Be Simplified

| Full System | Lightweight Alternative |
|-------------|------------------------|
| Multiple fuzzing engines | Single libFuzzer/AFL++ |
| Distributed Kafka architecture | Local execution |
| SymCC/Z3 concolic | LLM-guided input generation |
| Multiple LLM agents | Single Claude-based agent |
| Kubernetes orchestration | Local Docker or native |
| Complex seed scheduling | Simple round-robin |

### 13.5 Essential Components

1. **Code analysis tools**: Tree-sitter or simple AST parsing
2. **Build system integration**: Compile and run tests
3. **Crash detection**: Run with ASan, capture output
4. **LLM integration**: Claude API for analysis/generation
5. **Feedback loop**: Parse errors, retry with context

---

## Appendix: File Reference

| Component | Location |
|-----------|----------|
| UniAFL Core | `crs-multilang/uniafl/src/msa/` |
| Concolic | `crs-multilang/uniafl/src/concolic/` |
| Testlang | `crs-multilang/testlang/src/` |
| MLLA | `crs-multilang/blob-gen/multilang-llm-agent/mlla/` |
| DeepGen | `crs-userspace/deepgen_service/` |
| Directed Fuzzing | `crs-userspace/directed_fuzzing/Bullseye/` |
| Java CRS | `crs-java/crs/javacrs_modules/` |
| LLM-POC-Gen | `crs-java/crs/llm-poc-gen/vuli/` |
| ExpKit | `crs-java/crs/expkit/` |
| Patch Agents | `crs-patch/packages/crete/framework/agent/services/` |
| Static Analysis | `crs-sarif/sarif/validator/reachability/` |
