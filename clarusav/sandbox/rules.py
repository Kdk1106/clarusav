"""Config-driven behavioral rule engine evaluating execution traces."""

from dataclasses import asdict, dataclass
from typing import Any

from clarusav.config import SandboxRulesConfig, load_config
from clarusav.sandbox.trace import ExecutionTrace


@dataclass
class BehaviorAlert:
    rule_id: str
    severity: str
    description: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BehavioralRuleEngine:
    """Config-driven engine for evaluating execution traces against behavioral rules."""

    def __init__(self, rules_config: SandboxRulesConfig | None = None) -> None:
        if rules_config is None:
            cfg = load_config()
            self.rules = cfg.sandbox.rules
        else:
            self.rules = rules_config

    def evaluate(self, trace: ExecutionTrace) -> tuple[str, list[BehaviorAlert], str]:
        """Evaluate an execution trace and emit a behavioral verdict and alerts.

        Returns:
            Tuple of (verdict, alerts, reason_summary).
            Verdict is one of:
              - "MALICIOUS"
              - "BENIGN"
              - "UNRESOLVED - manual review"
        """
        trace.compute_metrics()
        alerts: list[BehaviorAlert] = []

        # Rule 0: Failure and ambiguity handling (MANDATORY REQUIREMENT)
        # Failures (container error, timeout, no behaviour observed) produce UNRESOLVED, never benign.
        if trace.timed_out:
            return (
                "UNRESOLVED - manual review",
                [],
                "Execution timed out before clean termination; potential sandbox evasion or stall.",
            )

        if trace.error_message:
            return (
                "UNRESOLVED - manual review",
                [],
                f"Container execution error encountered: {trace.error_message}",
            )

        if len(trace.processes) == 0 and len(trace.file_events) == 0:
            return (
                "UNRESOLVED - manual review",
                [],
                "No execution behavior observed in sandbox; manual review required.",
            )

        # Rule 1: Bulk modification detection
        bulk_cfg = self.rules.bulk_modification
        if bulk_cfg.enabled:
            if (
                trace.total_file_writes >= bulk_cfg.min_file_writes
                and trace.write_rate_per_sec >= bulk_cfg.min_write_rate_per_sec
            ):
                alerts.append(
                    BehaviorAlert(
                        rule_id="bulk_modification",
                        severity=bulk_cfg.severity,
                        description="Rapid burst of file modifications detected exceeding safety threshold.",
                        evidence={
                            "total_file_writes": trace.total_file_writes,
                            "write_rate_per_sec": round(trace.write_rate_per_sec, 2),
                            "threshold_writes": bulk_cfg.min_file_writes,
                            "threshold_rate": bulk_cfg.min_write_rate_per_sec,
                        },
                    )
                )

        # Rule 2: Ransomware mass-rename & extension changes
        rename_cfg = self.rules.ransomware_mass_rename
        if rename_cfg.enabled:
            if (
                trace.mass_renames_detected >= rename_cfg.min_mass_renames
                or len(trace.extension_changes) >= 2
            ):
                alerts.append(
                    BehaviorAlert(
                        rule_id="ransomware_mass_rename",
                        severity=rename_cfg.severity,
                        description="Mass file rename patterns or extension shifts indicative of ransomware.",
                        evidence={
                            "mass_renames_detected": trace.mass_renames_detected,
                            "extension_changes": trace.extension_changes,
                            "threshold_renames": rename_cfg.min_mass_renames,
                        },
                    )
                )

        # Rule 3: Suspicious process spawns
        proc_cfg = self.rules.suspicious_process_spawn
        if proc_cfg.enabled:
            suspicious_targets = {p.lower() for p in proc_cfg.suspicious_processes}
            for proc in trace.processes:
                p_name = proc.name.lower()
                cmd = " ".join(proc.cmdline).lower()
                if p_name in suspicious_targets or any(s in cmd for s in suspicious_targets):
                    alerts.append(
                        BehaviorAlert(
                            rule_id="suspicious_process_spawn",
                            severity=proc_cfg.severity,
                            description=f"High-risk process spawned in sandbox: {proc.name}",
                            evidence={
                                "process_name": proc.name,
                                "pid": proc.pid,
                                "cmdline": proc.cmdline,
                            },
                        )
                    )

        # Final verdict determination
        if alerts:
            summary = f"Triggered {len(alerts)} behavioral rule alert(s): " + ", ".join(
                f"{a.rule_id} ({a.severity})" for a in alerts
            )
            return "MALICIOUS", alerts, summary

        return "BENIGN", [], "Normal sandbox execution with benign process and filesystem activity."
