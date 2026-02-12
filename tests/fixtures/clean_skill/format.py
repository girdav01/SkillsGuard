"""Simple code formatting utility."""


def format_python(code: str) -> str:
    """Apply basic Python formatting."""
    lines = code.splitlines()
    formatted = []
    for line in lines:
        # Remove trailing whitespace
        cleaned = line.rstrip()
        formatted.append(cleaned)
    return "\n".join(formatted)


def format_json(code: str) -> str:
    """Pretty-print JSON."""
    import json
    parsed = json.loads(code)
    return json.dumps(parsed, indent=2)
