# FlagScent – Requirements Definition (PoC)

## 1. Overview

FlagScent is a proof-of-concept (PoC) reverse engineering assistance tool designed to automatically analyze Linux ELF binaries and extract **flag-like candidates** typically found in CTF reversing challenges.

The goal of the PoC is **not full automation**, but to demonstrate that combining static analysis, dynamic tracing, and heuristic scoring can reliably surface strong flag candidates with clear explanations.

The tool can be installed using pip.

---

## 2. Goals

### 2.1 Primary Goals

* Accept a single ELF binary as input
* Perform automated reverse engineering analysis
* Output **multiple ranked flag candidates**
* Provide **explainable sources** for each candidate (e.g. strings, trace, symbolic path)

### 2.2 Non-Goals (PoC Scope Exclusions)

* Guaranteed flag recovery
* Advanced obfuscation / VM / self-modifying code handling
* Anti-debugging bypass
* GUI or web interface
* Cross-platform support (Linux only)

---

## 3. Target Environment

* OS: Linux (x86_64)
* Python: 3.11+
* External tools:

  * radare2
  * ltrace
  * strace

---

## 4. PoC Target Problem Set

The PoC evaluation uses **10 reversing challenges**, categorized to highlight different strengths and limitations of FlagScent.

| Category | Description                                  | Count |
| -------- | -------------------------------------------- | ----- |
| A        | Direct strcmp / memcmp comparison            | 2     |
| B        | Light transformation (XOR / ROT / ADD)       | 2     |
| C        | Runtime-generated / trace-visible flags      | 2     |
| D        | Success-string / symbolic execution friendly | 2     |
| E        | Noisy / misleading / partial flag cases      | 2     |

Each category is expected to demonstrate either a successful extraction or a meaningful partial result.

---

## 5. Functional Requirements

### 5.1 Input

* Single ELF binary file
* Executable permission not required (tool may invoke execution via interpreter)

### 5.2 Static Analysis

* Extract printable strings
* Identify imported libc functions (e.g. strcmp, memcmp, puts)
* Detect cross-references to candidate strings

**Technology:** radare2 + r2pipe

---

### 5.3 Dynamic Analysis

#### ltrace

* Capture calls to:

  * strcmp / strncmp
  * memcmp
  * puts / printf
* Extract comparison arguments when possible

#### strace (supplementary)

* Monitor read / write syscalls
* Identify input/output behavior

---

### 5.4 Symbolic Execution (Optional, Time-Limited)

* Attempt path exploration toward success output strings (e.g. "Correct", "Success")
* Generate candidate stdin constraints

**Technology:** angr

---

### 5.5 Heuristic Analysis

FlagScent must apply heuristic analysis to extracted strings and generated values, including:

* Flag prefix detection (CTF{, flag{, etc.)
* Printable character ratio
* Entropy estimation
* Bracket balance validation
* Reasonable length range (15–80 chars)

---

### 5.6 Scoring and Ranking

Each candidate is assigned a numerical score based on heuristic evaluation and source reliability.

Example scoring components:

* Prefix match score
* Printability score
* Entropy score
* Structural validity score
* Source confidence (trace > symbolic > static)

Candidates are sorted in descending score order.

---

## 6. Output Requirements

### 6.1 CLI Output

* Ranked list of flag candidates
* Display score and extraction source

Example:

```
[1] score=92  CTF{rev_is_fun}
    source: ltrace strcmp @ main+0x123
```

### 6.2 Machine-Readable Output

* JSON format including:

  * candidate string
  * score
  * source
  * analysis method

---

## 7. Explainability Requirement

Every candidate must include:

* Extraction method (static / dynamic / symbolic)
* Origin reference (function name, syscall, or path)

This requirement is mandatory even for partial or incorrect candidates.

---

## 8. Success Criteria

The PoC is considered successful if:

* Correct flag appears within top 3 candidates in most Category A–D challenges
* Partial or informative candidates appear in Category E challenges
* Output clearly explains *why* each candidate was produced

---

## 9. Future Extensions (Out of Scope for PoC)

* Obfuscation pattern detection
* Custom VM analysis
* Windows PE support
* Distributed / batch analysis
* IDE or web integration

---

## 10. Project Identity

* Tool Name: **FlagScent**
* Purpose: Automated flag candidate discovery for CTF reverse engineering
* Design Philosophy: "Smell the flag, don’t brute-force it."
