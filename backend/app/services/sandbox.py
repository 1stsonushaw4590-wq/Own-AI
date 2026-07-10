import asyncio
import tempfile
import os
import subprocess
from app.core.config import get_settings


class SandboxService:
    def __init__(self):
        self.settings = get_settings()
        self.image = "cyber-llm-sandbox:latest"
        self.timeout = self.settings.sandbox_timeout

    async def execute(self, code: str, language: str = "python", timeout: int = 25) -> dict:
        ext = {
            "python": ".py", "bash": ".sh", "cpp": ".cpp",
            "c": ".c", "go": ".go", "rust": ".rs",
            "javascript": ".js", "typescript": ".ts",
            "java": ".java", "php": ".php",
        }
        suffix = ext.get(language, ".py")
        interpreter = {
            "python": "python3",
            "bash": "bash",
            "cpp": "g++ -o /tmp/a.out /sandbox/code.py && /tmp/a.out",
            "c": "gcc -o /tmp/a.out /sandbox/code.py && /tmp/a.out",
            "go": "go run /sandbox/code.py",
            "rust": "rustc -o /tmp/a.out /sandbox/code.py && /tmp/a.out",
            "javascript": "node",
            "typescript": "deno run",
            "java": "java",
            "php": "php",
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False
        ) as f:
            f.write(code)
            path = f.name

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "run", "--rm",
                "--network", "none",
                "--read-only",
                "--security-opt", "no-new-privileges",
                "--cap-drop", "ALL",
                "--memory", "256m",
                "--cpus", "1.0",
                "-v", f"{path}:/sandbox/code.py:ro",
                self.image,
                *interpreter.get(language, "python3").split(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": "",
                    "timed_out": True,
                }

            return {
                "exit_code": proc.returncode or 0,
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
                "timed_out": False,
            }
        finally:
            os.unlink(path)


sandbox = SandboxService()
