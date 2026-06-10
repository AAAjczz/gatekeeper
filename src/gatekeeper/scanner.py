"""AI Infrastructure Security Auditor.

Scans your AI API deployment for configuration-level vulnerabilities —
the stuff garak and augustus don't test. Docker config, secrets, CORS,
rate limiting, access control, network exposure.
"""

import os
from typing import Optional

from .probes import (
    FILE_PROBES,
    NETWORK_PROBES,
    FILE_PROBE_COUNT,
    NETWORK_PROBE_COUNT,
    AuditFinding,
)


class Auditor:
    """Audit an AI API deployment for infrastructure-level security issues."""

    def __init__(
        self,
        project_dir: str = ".",
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        verbose: bool = False,
    ):
        self.project_dir = os.path.abspath(project_dir)
        self.endpoint = endpoint.rstrip("/") if endpoint else None
        self.api_key = api_key or "sk-test"
        self.verbose = verbose

        # Resolve common config file paths
        self.docker_compose = self._find_file(["docker-compose.yml", "docker-compose.yaml"])
        self.config_file = self._find_file(["config.yaml", "config.yml", "litellm_config.yaml"])

    def _find_file(self, candidates: list[str]) -> Optional[str]:
        for name in candidates:
            path = os.path.join(self.project_dir, name)
            if os.path.isfile(path):
                return path
        return os.path.join(self.project_dir, candidates[0])  # default for checks

    def run_file_probes(self) -> list[AuditFinding]:
        """Run all file-based probes."""
        results = []
        docker_path = self.docker_compose or os.path.join(self.project_dir, "docker-compose.yml")
        config_path = self.config_file or os.path.join(self.project_dir, "config.yaml")

        for i, probe_fn in enumerate(FILE_PROBES):
            fn_name = probe_fn.__name__

            # Route appropriate probes
            if "ports" in fn_name:
                result = probe_fn(docker_path)
            elif "deploy_" in fn_name:
                result = probe_fn(docker_path)
            elif "rate_limit" in fn_name:
                result = probe_fn(self.project_dir)  # now takes project_dir
            elif "resource" in fn_name:
                result = probe_fn(docker_path)
            else:
                result = probe_fn(self.project_dir)

            results.append(result)
            if self.verbose:
                status = "PASS" if result.passed else "FAIL"
                print(f"  [{i+1:2d}/{FILE_PROBE_COUNT}] {result.id} "
                      f"{result.name[:45]:<45s} {status}")

        return results

    def run_network_probes(self) -> list[AuditFinding]:
        """Run all network-based probes."""
        if not self.endpoint:
            return []

        results = []
        docker_path = self.docker_compose or os.path.join(self.project_dir, "docker-compose.yml")

        for i, probe_fn in enumerate(NETWORK_PROBES):
            fn_name = probe_fn.__name__

            if "ports" in fn_name:
                result = probe_fn(docker_path)
            elif "cors" in fn_name or "no_auth" in fn_name or "model_permissions" in fn_name:
                result = probe_fn(self.endpoint, self.api_key)
            elif "https" in fn_name:
                result = probe_fn(self.endpoint)
            elif "exposed_admin" in fn_name:
                result = probe_fn(self.endpoint, self.api_key)
            else:
                continue

            results.append(result)
            if self.verbose:
                status = "PASS" if result.passed else "FAIL"
                print(f"  [{FILE_PROBE_COUNT + i + 1:2d}/{FILE_PROBE_COUNT + NETWORK_PROBE_COUNT}] "
                      f"{result.id} {result.name[:45]:<45s} {status}")

        return results

    def audit(self) -> list[AuditFinding]:
        """Run full audit — file checks + network checks if endpoint provided."""
        results = self.run_file_probes()
        if self.endpoint:
            results.extend(self.run_network_probes())
        return results

    def summary(self, results: list[AuditFinding]) -> dict:
        """Generate summary statistics."""
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed

        by_severity = {}
        by_category = {}
        for r in results:
            # Categorize
            by_category.setdefault(r.category, {"total": 0, "passed": 0})
            by_category[r.category]["total"] += 1
            if r.passed:
                by_category[r.category]["passed"] += 1

            # Severity of failures
            if not r.passed:
                by_severity.setdefault(r.severity, 0)
                by_severity[r.severity] += 1

        score = round(passed / total * 100, 1) if total > 0 else 0

        return {
            "project_dir": self.project_dir,
            "endpoint": self.endpoint or "N/A (file-only audit)",
            "total_probes": total,
            "passed": passed,
            "failed": failed,
            "score": score,
            "failed_by_severity": by_severity,
            "by_category": by_category,
            "interpretation": self._interpret(score),
            "note": "This audits DEPLOYMENT security, not model security. "
                    "For model-level red-teaming, use garak or augustus.",
        }

    @staticmethod
    def _interpret(score: float) -> str:
        if score >= 95:
            return "Deployment looks solid — production-ready"
        elif score >= 80:
            return "Good baseline — a few items need attention"
        elif score >= 60:
            return "Several gaps — fix before exposing to the internet"
        elif score >= 40:
            return "Serious issues — do not deploy publicly yet"
        else:
            return "Critical vulnerabilities — major reconfiguration needed"
