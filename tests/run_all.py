# tests/run_all.py
"""Runs every test file and prints one ALL PASS, or the failures. Nothing here touches a real tenant."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS = (
    ("test_interview.cjs", ["node"]),
    ("test_planner.cjs", ["node"]),
    ("test_helper.py", [sys.executable, "-B"]),
)


def main():
    failures = []
    for name, command in RUNS:
        try:
            done = subprocess.run(command + [os.path.join(HERE, name)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            text = done.stdout.decode("utf-8", "replace")
            passed = done.returncode == 0 and text.strip().splitlines()[-1:] == ["ALL PASS"]
        except OSError as error:
            text, passed = "Could not start %s: %s" % (command[0], error), False
        print("%-20s %s" % (name, "pass" if passed else "FAIL"))
        for line in text.splitlines():
            if line.startswith("SKIPPED"):
                print("  " + line)
        if not passed:
            failures.append((name, text))
    if failures:
        for name, text in failures:
            print("")
            print("----- " + name + " -----")
            print(text.rstrip())
        print("")
        print("%d of %d test files failed." % (len(failures), len(RUNS)))
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
