import hashlib
import subprocess

import requests


API_KEY = "hardcoded-secret-value"


def run_demo() -> None:
    subprocess.run("echo hello", shell=True, check=False)
    requests.get("https://example.com", verify=False, timeout=5)
    hashlib.md5(b"demo").hexdigest()
