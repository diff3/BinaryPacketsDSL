# Contributing to PyPandariaEmu



## Code Style & Naming Conventions

This project follows **PEP 8** and **NASA's coding standards**, with few intentional deviation:



### **File & Directory Naming**
- **Directories use lowercase (snake_case).**
- **Files use CamelCase to match class names.**

**Reference:**

- **PEP 8 - Python Style Guide**: [https://peps.python.org/pep-0008/](https://peps.python.org/pep-0008/)



### **NASA Coding Standards Applied**

1. **Explicit & Clear Code** – No magic numbers, meaningful variable names.
2. **Functions & Classes Must Have a Single Responsibility** – Avoid complexity.
3. **Always Return a Value** – Even if it's `None` or an error code.
4. **Error Handling is Mandatory** – No silent failures.
5. **No Global Variables** – Use dependency injection or class attributes.
   1. config is exluded for simplicity, but add "global config" at the beggining of all methods and functions.

6. **Type Annotations Required** – Ensures maintainability and readability.
7. **Thread-Safety Considered** – Especially in network-related operations.
8. **Minimized Code Duplication** – Reuse functions and classes.
9. **Code Must Be Readable & Maintainable**
   - The **next developer** should be able to understand your code **without excessive documentation**.
   - Use **consistent formatting** and follow naming conventions.
10. **Testing & Verification is Essential**

- Code **must be tested** (unit tests, integration tests).
- Avoid assumptions – **test edge cases and failure scenarios**.



## Contribution Guidelines

1. Follow the naming conventions above.
2. Ensure code adheres to **PEP 8** and **NASA coding standards**.
3. Submit a well-documented pull request.



### **Docstring Guidelines**

All **classes, methods, and functions must have a docstring** that explains their purpose **clearly but concisely**.

### **Key Principles**

1. **Be concise but informative** – Avoid stating the obvious.
2. **Use meaningful names** – Reduce the need for excessive comments.
3. **Follow structured formats** – Use **Google-style** or **NumPy-style** docstrings.
4. **Always document return values**, even if it's `None`.



###  **When to Include `Returns:` in the Docstring?**

1. **If the return type is obvious (`-> None`, `-> int`, `-> str`)**, you can skip it.
2. **If the function returns multiple possible types (`-> int | None`)**, document what each case means.
3. **If the return value needs explanation (e.g., a custom object, special logic, or error handling),** document it.



```python
def add_numbers(a: int, b: int) -> int:
    """Returns the sum of two integers."""
    return a + b

class SessionManager:
	"""Manages active user sessions."""

	def add_session(self, client_ip: str, username: str) -> None:
  	"""Registers a session for a given client IP.

    	Args:
      	client_ip (str): The IP address of the client.
     		username (str): The associated username.
   	"""
        
  def process_data(data: list[int]) -> dict[str, float]:
  	"""Processes numerical data and returns computed statistics.

    Args:
   		data (list[int]): A list of integers representing raw data.

   	Returns:
   		dict[str, float]: A dictionary containing statistical results.
    """
```



### Testing Guidelines 



We use **NASA-inspired testing** for reliability, but don’t worry—it’s simple!   The goal is to make sure code is **predictable, robust, and failure-proof**.   

## Minimum Test Requirements 

**1. Test normal use cases** (expected input & output).  

 **2. Test edge cases** (empty data, limits, invalid values).  

 **3. Test error handling** (ensure failures are predictable).   



**Example:** 

```python
import pytest
from manager.SessionManager import SessionManager

@pytest.fixture
def session_manager():
    """Creates a fresh SessionManager instance for each test."""
    return SessionManager()

def test_add_and_get_session(session_manager):
    """Ensures a session can be added and retrieved correctly."""
    session_manager.add_session("192.168.1.1", "user1")
    assert session_manager.get_username("192.168.1.1") == "user1"

def test_get_username_not_found(session_manager):
    """Returns None when the session does not exist."""
    assert session_manager.get_username("192.168.1.99") is None

def test_remove_session(session_manager):
    """Ensures session removal works as expected."""
    session_manager.add_session("192.168.1.1", "user1")
    assert session_manager.remove_session("192.168.1.1") is True
    assert session_manager.get_username("192.168.1.1") is None

def test_remove_nonexistent_session(session_manager):
    """Returns False when trying to remove a non-existent session."""
    assert session_manager.remove_session("192.168.1.99") is False

```



Run the test from terminal
```shell
pytest tests/
============================== test session starts ==============================
collected 4 items

tests/TestSessionManager.py ....  [100%]

============================== 4 passed in 0.12s ===============================

```





 don’t need **hundreds of tests**—just ensure your code works in **all expected scenarios**.

 **Write meaningful tests, and debugging will be easier for everyone!**



Thank you for contributing!