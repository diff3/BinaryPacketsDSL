# state_machine.py

def update_state(state, data, direction):
    """
    Inspect raw traffic and update session state.
    No side effects outside state.
    """
    # Example placeholders
    if state.phase == "auth" and b"WORLD" in data:
        state.phase = "world"

    if not state.encrypted and b"CRYPTO_ON" in data:
        state.encrypted = True