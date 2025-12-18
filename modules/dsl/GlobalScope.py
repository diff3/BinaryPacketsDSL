# globalScope.py

class GlobalScope:
    """
    Variabelhantering för DSL:
    - global_vars: globala variabler
    - scope_stack: lokala scopes (loop, if-block)
    - loop_index: håller reda på aktuellt index per loopad lista
    """

    def __init__(self):
        self.global_vars = {}     # permanenta variabler
        self.scope_stack = []     # lokala scopes (loop, if-block)
        self.loop_index = {}      # <-- NY: {"realm_bits": 0, "races": 3, ...}

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
    # RESET (viktigt inför varje decode)
    # -------------------------------------------------
    def reset(self):
        """Nollställ allt state inför ny decoding."""
        self.global_vars.clear()
        self.scope_stack.clear()
        self.loop_index.clear()     # <-- NYTT

    # -------------------------------------------------
    # DEBUG
    # -------------------------------------------------
    def dump(self):
        print("GLOBAL:", self.global_vars)
        for i, scope in enumerate(self.scope_stack):
            print(f"LOCAL[{i}]:", scope)
        print("LOOP_INDEX:", self.loop_index)

    def get_all(self):
        """Return a plain dict of all variables."""
        return dict(self.global_vars)
    
    def set_all(self, mapping):
        # Runtime-mode: accept and store but do not enforce DSL scoping rules
        for k, v in mapping.items():
            self._data[k] = v
    
    