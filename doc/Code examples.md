# NASA Programming Guidelines Adapted for Python

This document summarizes key programming principles inspired by NASA’s software engineering standards, adapted for use in Python-based tooling such as BinaryPacketsDSL.

The goal is to promote:
	•	Clarity – code should be easy to read and reason about
	•	Robustness – handle errors explicitly and predictably
	•	Testability – keep logic modular and verifiable
	•	Maintainability – avoid unnecessary complexity or dependencies
	•	Traceability – every decision and behavior should be observable and explainable

These principles are especially valuable in systems that must process binary data with precision, where safety, correctness, and reproducibility are critical.

Each section below includes clear examples of both good and bad practices, with a focus on practical patterns you can apply in BinaryPacketsDSL and similar tools.


## 1. Avoid Dynamic Memory Allocation During Runtime

Avoid creating or managing resources during runtime that could lead to inefficiency or bugs.

```python
# Good Example
with open('file.txt', 'r') as f:
    data = f.read()

# Bad Example
f = open('file.txt', 'r')
data = f.read()
f.close()  # Forgetting to close can cause resource leaks
```

---

## 2. Always Use Static Analysis

Use tools to catch issues before runtime, like type-checkers and linters.

```python
# Use type annotations

def add_numbers(a: int, b: int) -> int:
    return a + b

# Tools: flake8, pylint, mypy
```

---

## 3. Avoid Complexity and Use Simple Constructs

Simplify logic and break up long functions into smaller, manageable parts.

```python
# Good Example
def process_data(data):
    if data:
        return [x * 2 for x in data]
    return []

# Bad Example
def process_data(data):
    return [x * 2 for x in data] if data else []
```

---

## 4. Always Perform Code Reviews

Standardize code reviews as part of the development process. Use tools like `black` to format code consistently.

---

## 5. Use Defensive Programming

Validate inputs and handle errors explicitly.

```python
# Good Example
def divide(a: float, b: float) -> float:
    if b == 0:
        raise ValueError("b cannot be 0")
    return a / b

# Bad Example
def divide(a, b):
    return a / b  # Risk of ZeroDivisionError
```

---

## 6. Avoid Global State

Encapsulate data and logic inside functions or classes to prevent unexpected side effects.

```python
# Good Example
class Counter:
    def __init__(self):
        self.count = 0

    def increment(self):
        self.count += 1

# Bad Example
counter = 0

def increment():
    global counter
    counter += 1
```

---

## 7. Limit External Dependencies

Minimize reliance on third-party libraries to reduce potential vulnerabilities.

```python
# Good Example
import csv

# Bad Example
import pandas  # Overkill for simple CSV tasks
```

---

## 8. Use Unit Tests and Code Coverage

Write unit tests to verify the functionality of each part of your code.

```python
def add(a, b):
    return a + b

# Test

def test_add():
    assert add(2, 3) == 5
    assert add(-1, 1) == 0
```

Use tools like `pytest` to automate testing and measure test coverage.

---

## 9. Document Everything

Write clear and concise documentation using docstrings.

```python
def factorial(n: int) -> int:
    """
    Calculate the factorial of a non-negative integer n.

    :param n: A non-negative integer
    :return: The factorial of n
    """
    if n == 0:
        return 1
    return n * factorial(n - 1)
```

---

## 10. Avoid Unstructured Control Flow

Avoid creating confusing or hard-to-follow control flows.

```python
# Good Example
for item in data:
    if not condition(item):
        break

# Bad Example
i = 0
while i < len(data):
    if not condition(data[i]):
        break
    i += 1
```