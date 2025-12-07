# globalScope.py

class GlobalScope:
    """
    Minimal variabelhantering för DSL:
    - global scope
    - lokala scopes (stack)
    - lookup med lokal → global resolution
    """

    def __init__(self):
        self.global_vars = {}     # permanenta variabler
        self.scope_stack = []     # lokala scopes (loop, if-block)

    # -------------------------------------------------
    # GET VARIABLE
    # -------------------------------------------------
    def get(self, name, default=None):
        # sök lokalt (inner → outer)
        for scope in reversed(self.scope_stack):
            if name in scope:
                return scope[name]

        # sök globalt
        return self.global_vars.get(name, default)

    # -------------------------------------------------
    # SET VARIABLE
    # -------------------------------------------------
    def set(self, name, value):
        if self.scope_stack:
            # om vi befinner oss i ett block, sätt lokalt
            self.scope_stack[-1][name] = value
        else:
            # annars globalt
            self.global_vars[name] = value

    # -------------------------------------------------
    # DELETE VARIABLE
    # -------------------------------------------------
    def delete(self, name):
        # radera lokalt först
        for scope in reversed(self.scope_stack):
            if name in scope:
                del scope[name]
                return

        # radera globalt
        if name in self.global_vars:
            del self.global_vars[name]

    # -------------------------------------------------
    # SCOPE CONTROL (loop/if-block)
    # -------------------------------------------------
    def push(self):
        """Öppna ett nytt lokalt scope."""
        self.scope_stack.append({})

    def pop(self):
        """Stäng senaste lokala scopet."""
        if not self.scope_stack:
            raise RuntimeError("Scope stack underflow")
        self.scope_stack.pop()

    # -------------------------------------------------
    # DEBUG
    # -------------------------------------------------
    def dump(self):
        print("GLOBAL:", self.global_vars)
        for i, scope in enumerate(self.scope_stack):
            print(f"LOCAL[{i}]:", scope)