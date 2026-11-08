"""Optional read-only SETools adapter for compiled Android SELinux policies.

Only explicitly supplied policy files are processed. Commands use argv (never a shell),
a timeout, bounded output, and do not modify the policy.
"""
from __future__ import annotations
from pathlib import Path
import shutil
import subprocess

MAX_POLICY_BYTES = 128 * 1024 * 1024
MAX_OUTPUT_CHARS = 20000

def inspect_compiled_policy(policy: Path, timeout: int = 30) -> dict:
    policy = Path(policy)
    if policy.is_symlink() or not policy.is_file():
        raise ValueError("Policy must be an existing regular file, not a symlink")
    size = policy.stat().st_size
    if size <= 0 or size > MAX_POLICY_BYTES:
        raise ValueError(f"Policy size must be between 1 and {MAX_POLICY_BYTES} bytes")
    if timeout < 1 or timeout > 300:
        raise ValueError("timeout must be between 1 and 300 seconds")
    tools = {name: shutil.which(name) for name in ("seinfo", "sesearch")}
    result = {"policy": str(policy), "size_bytes": size, "tools": tools,
              "commands": [], "limitations": [
                  "SETools output is a policy query, not proof of runtime reachability or exploitability.",
                  "Android policy may combine vendor-specific attributes and build-time macros not represented by these focused queries.",
                  "No policy changes are made."]}
    if not all(tools.values()):
        result["available"] = False
        result["missing_tools"] = [name for name, path in tools.items() if not path]
        return result
    commands = [
        ["seinfo", "--stats", str(policy)],
        ["sesearch", "--allow", "-s", "adbd", str(policy)],
        ["sesearch", "--allow", "-t", "mtp", str(policy)],
    ]
    result["available"] = True
    for argv in commands:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                  check=False, shell=False)
            result["commands"].append({"argv": argv[:3] + ["<policy>"],
                                       "returncode": proc.returncode,
                                       "stdout": proc.stdout[:MAX_OUTPUT_CHARS],
                                       "stderr": proc.stderr[:4000],
                                       "truncated": len(proc.stdout) > MAX_OUTPUT_CHARS})
        except subprocess.TimeoutExpired:
            result["commands"].append({"argv": argv[:3] + ["<policy>"], "error": "timeout"})
        except OSError as exc:
            result["commands"].append({"argv": argv[:3] + ["<policy>"], "error": str(exc)})
    return result
