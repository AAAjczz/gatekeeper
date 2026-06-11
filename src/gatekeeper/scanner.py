"""AI Infrastructure Security Auditor.

Scans your AI API deployment for configuration-level vulnerabilities —
the stuff garak and augustus don't test. Docker config, secrets, CORS,
rate limiting, access control, network exposure.
"""

import os
from typing import Optional

import yaml
from yaml import YAMLError

from .probes import (
    FILE_PROBES,
    NETWORK_PROBES,
    FILE_PROBE_COUNT,
    NETWORK_PROBE_COUNT,
    AuditFinding,
)

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _load_gatekeeper_config(project_dir: str) -> dict:
    """Load .gatekeeper.yaml config file if it exists."""
    config_path = os.path.join(project_dir, ".gatekeeper.yaml")
    if not os.path.isfile(config_path):
        return {}
    try:
        with open(config_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return cfg
    except YAMLError:
        return {}


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

        # Load user config
        self.config = _load_gatekeeper_config(self.project_dir)

        # Resolve common config file paths
        self.docker_compose = self._find_file(["docker-compose.yml", "docker-compose.yaml"])
        self.config_file = self._find_file(["config.yaml", "config.yml", "litellm_config.yaml"])

    def _find_file(self, candidates: list[str]) -> Optional[str]:
        for name in candidates:
            path = os.path.join(self.project_dir, name)
            if os.path.isfile(path):
                return path
        return os.path.join(self.project_dir, candidates[0])  # default for checks

    def _run_probe_list(self, probes: list, probe_args: dict, offset: int = 0,
                        total: int = 0) -> list[AuditFinding]:
        """Run a list of probes using a dispatch table for argument routing.

        probe_args maps probe function -> args tuple. Probes not in the map
        receive (self.project_dir,) by default for file probes, or raise for
        network probes (all network probes MUST be in the map).
        """
        results = []
        for i, probe_fn in enumerate(probes):
            if probe_fn in probe_args:
                args = probe_args[probe_fn]
            elif probe_args is self._NETWORK_ARGS:
                raise TypeError(
                    f"Network probe '{probe_fn.__name__}' has no entry in "
                    f"_NETWORK_ARGS dispatch table. Add it to scanner.py."
                )
            else:
                args = (self.project_dir,)

            result = probe_fn(*args)
            results.append(result)
            if self.verbose:
                status = "PASS" if result.passed else "FAIL"
                count = total if total else len(probes)
                print(f"  [{offset + i + 1:2d}/{count}] {result.id} "
                      f"{result.name[:45]:<45s} {status}")
        return results

    def run_file_probes(self) -> list[AuditFinding]:
        """Run all file-based probes."""
        docker_path = self.docker_compose or os.path.join(self.project_dir, "docker-compose.yml")

        # Dispatch table: probe function -> arguments tuple
        file_args = {}
        for fn in FILE_PROBES:
            name = fn.__name__
            if "deploy_" in name or "ports" in name or "resource" in name:
                file_args[fn] = (docker_path,)
            elif "rate_limit" in name:
                file_args[fn] = (self.project_dir,)
            else:
                file_args[fn] = (self.project_dir,)

        return self._run_probe_list(FILE_PROBES, file_args, total=FILE_PROBE_COUNT)

    def run_network_probes(self) -> list[AuditFinding]:
        """Run all network-based probes."""
        if not self.endpoint:
            return []

        from .probes import (
            check_access_cors,
            check_access_no_auth,
            check_access_model_permissions,
            check_access_security_headers,
            check_network_https,
            check_network_tls_cert,
            check_network_exposed_admin,
            check_network_dangerous_methods,
            check_network_hsts,
            check_network_host_injection,
        )

        # Dispatch table by function reference — rename-safe, order-safe
        self._NETWORK_ARGS = {
            check_access_cors: (self.endpoint, self.api_key),
            check_access_no_auth: (self.endpoint,),
            check_access_model_permissions: (self.endpoint, self.api_key),
            check_access_security_headers: (self.endpoint,),
            check_network_https: (self.endpoint,),
            check_network_tls_cert: (self.endpoint,),
            check_network_exposed_admin: (self.endpoint, self.api_key),
            check_network_dangerous_methods: (self.endpoint,),
            check_network_hsts: (self.endpoint,),
            check_network_host_injection: (self.endpoint,),
        }

        return self._run_probe_list(
            NETWORK_PROBES, self._NETWORK_ARGS,
            offset=FILE_PROBE_COUNT,
            total=FILE_PROBE_COUNT + NETWORK_PROBE_COUNT,
        )

    def audit(self) -> list[AuditFinding]:
        """Run full audit — file checks + network checks if endpoint provided.

        Filters results based on .gatekeeper.yaml config:
        - ignore: list of probe IDs to skip
        - min_severity: minimum severity level to report (critical > high > medium > low > info)
        """
        results = self.run_file_probes()
        if self.endpoint:
            results.extend(self.run_network_probes())

        # Apply .gatekeeper.yaml filters
        if self.config:
            ignore_ids = self.config.get("ignore", [])
            if ignore_ids:
                results = [r for r in results if r.id not in ignore_ids]

            min_sev = self.config.get("min_severity", "info")
            min_rank = SEVERITY_RANK.get(min_sev.lower(), 0)
            results = [r for r in results if SEVERITY_RANK.get(r.severity, 0) >= min_rank]

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
