import os, json, logging, tempfile, subprocess, re, shutil, time
from typing import List, Optional
from analyzers.base import Finding

logger = logging.getLogger(__name__)
PROOFS_DIR = os.path.join(os.path.dirname(__file__), "proofs")
os.makedirs(PROOFS_DIR, exist_ok=True)

POC_PROMPT = """You are an expert in Foundry (Solidity testing framework). 
Write a complete Foundry test file (.t.sol) that PROVES the following vulnerability EXISTS.

Vulnerability: {vulnerability}
Severity: {severity}
Description: {description}

Victim Contract Code:
```solidity
{code}
```

Requirements:
1. Create a test that calls the vulnerable function with the EXACT attack payload
2. The test must REVERT or show state corruption if the vulnerability is real
3. Use `vm.startPrank(attacker)`, `deal()`, and other Foundry cheatcodes
4. Import `forge-std/Test.sol` and `../src/Victim.sol`
5. The test function name must start with `testPoC`
6. If it's a reentrancy, create an attacker contract that calls back
7. Add console.log assertions to prove the exploit worked
8. ONLY output the Solidity code, no explanation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
...
```
"""

POC_FRAMEWORK = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
{poc_body}
"""

FOUNDRY_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

{poc_code}
"""


DANGEROUS_CHEATCODES = [
    r"vm\.ffi\s*\(",
    r"vm\.broadcast\s*\(",
    r"vm\.startBroadcast\s*\(",
    r"vm\.stopBroadcast\s*\(",
    r"vm\.writeFile\s*\(",
    r"vm\.readFile\s*\(",
    r"vm\.removeFile\s*\(",
    r"vm\.createDir\s*\(",
    r"vm\.writeJson\s*\(",
    r"vm\.setEnv\s*\(",
    r"vm\.getEnv\s*\(",
    r"vm\.projectRoot\s*\(",
    r"vm\.envOr\s*\(",
    r"vm\.envBool\s*\(",
    r"vm\.envUint\s*\(",
    r"vm\.envInt\s*\(",
    r"vm\.envAddress\s*\(",
    r"vm\.envBytes32\s*\(",
    r"vm\.envString\s*\(",
    r"vm\.envBytes\s*\(",
    r"vm\.keyExists\s*\(",
    r"vm\.keyExistsJson\s*\(",
    r"vm\.serializeJson\s*\(",
    r"vm\.parseJson\s*\(",
    r"vm\.parseThomas\s*\(",
    r"vm\.linkSymbol\s*\(",
]

def _has_dangerous_cheatcodes(code: str) -> bool:
    for pattern in DANGEROUS_CHEATCODES:
        if re.search(pattern, code):
            return True
    return False

def _clean_poc(raw: str) -> str:
    """Extract Solidity code from LLM response."""
    m = re.search(r"```solidity\n?(.*?)```", raw, re.DOTALL)
    if m:
        return m.group(1).strip()
    m = re.search(r"```\n?(.*?)```", raw, re.DOTALL)
    if m:
        return m.group(1).strip()
    return raw.strip()


def generate_poc(finding: Finding, full_code: str) -> Optional[str]:
    from agents import call_model_with_fallback
    prompt = POC_PROMPT.format(
        vulnerability=finding.agent_name,
        severity=finding.severity,
        description=finding.description,
        code=full_code[:2000],
    )
    try:
        raw = call_model_with_fallback(prompt)
        code = _clean_poc(raw)
        if _has_dangerous_cheatcodes(code):
            logger.error(f"PoC for {finding.agent_name} contains dangerous cheatcodes (vm.ffi/vm.broadcast) — rejecting")
            return None
        if not code or len(code) < 100:
            logger.warning(f"PoC too short for {finding.agent_name}")
            return None
        safe = re.sub(r'[^a-zA-Z0-9_\u0600-\u06FF-]', '_', finding.agent_name)[:40]
        fname = f"PoC_{safe}_{finding.file.replace('/', '_')}.t.sol"
        path = os.path.join(PROOFS_DIR, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write(code)
        logger.info(f"PoC saved: {path}")
        return path
    except Exception as e:
        logger.warning(f"PoC generation failed: {e}")
        return None


def run_foundry_test(poc_path: str, project_dir: str = ".", use_docker: bool = True) -> dict:
    result = {"passed": False, "output": "", "error": ""}
    try:
        if use_docker:
            docker_path = shutil.which("docker")
            if not docker_path:
                result["error"] = "Docker not found. Install Docker: https://docs.docker.com/get-docker/"
                return result
            abs_poc = os.path.abspath(poc_path)
            poc_dir = os.path.dirname(abs_poc)
            poc_basename = os.path.basename(abs_poc)
            proc = subprocess.run(
                ["docker", "run", "--rm",
                 "-v", f"{poc_dir}:/poc:ro",
                 "ghcr.io/foundry-rs/foundry:latest",
                 "forge", "test", "--match-path", f"/poc/{poc_basename}",
                 "--no-match-coverage"],
                capture_output=True, text=True, timeout=120,
            )
        else:
            proc = subprocess.run(
                ["forge", "test", "--match-path", poc_path, "--no-match-coverage"],
                capture_output=True, text=True, timeout=120, cwd=project_dir,
            )
        result["output"] = proc.stdout + proc.stderr
        result["passed"] = proc.returncode == 0
        if "FAILED" in proc.stdout or "FAILED" in proc.stderr:
            result["passed"] = False
    except FileNotFoundError:
        result["error"] = "forge not installed. Install Foundry: https://book.getfoundry.sh/getting-started/installation"
    except subprocess.TimeoutExpired:
        result["error"] = "Test timed out (120s)"
    except Exception as e:
        result["error"] = str(e)
    return result


def _has_docker() -> bool:
    """Check if Docker CLI is available on the system."""
    return shutil.which("docker") is not None


def run_foundry_test_docker(code: str, proof_dir: str) -> str:
    """
    Run a Foundry PoC test inside a Docker container.

    Builds a Docker image with Foundry, writes the PoC code into a temporary
    Foundry project, mounts it as a volume, and executes `forge test` inside
    the container. Falls back to local subprocess execution if Docker is not
    available.

    Args:
        code: Raw Solidity source of the PoC test.
        proof_dir: Directory to use as the project root (for fallback and
                   dependency resolution).

    Returns:
        Combined stdout/stderr output as a string.
    """
    if not _has_docker():
        logger.info("Docker not available, falling back to subprocess")
        os.makedirs(proof_dir, exist_ok=True)
        safe_name = f"PoC_fallback_{int(time.time())}.t.sol"
        poc_path = os.path.join(proof_dir, safe_name)
        with open(poc_path, "w", encoding="utf-8") as f:
            f.write(code)
        result = run_foundry_test(poc_path, proof_dir)
        return result.get("output", "") or result.get("error", "")

    tmpdir = tempfile.mkdtemp(prefix="foundry_poc_")
    try:
        test_dir = os.path.join(tmpdir, "test")
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(test_dir)
        os.makedirs(src_dir)

        poc_path = os.path.join(test_dir, "PoC.t.sol")
        with open(poc_path, "w", encoding="utf-8") as f:
            f.write(code)

        dockerfile_path = os.path.join(tmpdir, "Dockerfile")
        with open(dockerfile_path, "w", encoding="utf-8") as f:
            f.write("FROM ghcr.io/foundry-rs/foundry:latest\nWORKDIR /app\n")

        build_proc = subprocess.run(
            ["docker", "build", "-t", "foundry-test", tmpdir],
            capture_output=True, text=True, timeout=60,
        )
        if build_proc.returncode != 0:
            raise RuntimeError(f"Docker build failed: {build_proc.stderr}")

        run_proc = subprocess.run(
            ["docker", "run", "--rm",
             "-v", f"{tmpdir}:/app",
             "-w", "/app",
             "foundry-test",
             "forge", "test", "--match-path", "test/PoC.t.sol", "-vvv"],
            capture_output=True, text=True, timeout=120,
        )
        output = run_proc.stdout + run_proc.stderr
        if run_proc.returncode != 0:
            logger.warning("Foundry test failed:\n%s", output)
        return output

    except subprocess.TimeoutExpired:
        return "Error: Test timed out (120s)"
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr or str(e)}"
    except Exception as e:
        return f"Error: {e}"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def batch_generate_pocs(findings: List[Finding], codes: dict) -> List[dict]:
    results = []
    for f in findings:
        code = codes.get(f.file, "")
        if not code:
            continue
        path = generate_poc(f, code)
        if path:
            results.append({"finding": f, "poc_path": path, "status": "generated"})
        else:
            results.append({"finding": f, "poc_path": None, "status": "failed"})
    return results
