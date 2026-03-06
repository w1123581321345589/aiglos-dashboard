import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const severityConfig: Record<string, { className: string; label: string }> = {
  critical: {
    className: "bg-red-500/15 text-red-400 dark:text-red-400 border-red-500/20",
    label: "Critical",
  },
  high: {
    className: "bg-orange-500/15 text-orange-500 dark:text-orange-400 border-orange-500/20",
    label: "High",
  },
  medium: {
    className: "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/20",
    label: "Medium",
  },
  low: {
    className: "bg-blue-500/15 text-blue-500 dark:text-blue-400 border-blue-500/20",
    label: "Low",
  },
  info: {
    className: "bg-slate-500/15 text-slate-500 dark:text-slate-400 border-slate-500/20",
    label: "Info",
  },
};

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const config = severityConfig[severity] || severityConfig.info;
  return (
    <Badge
      variant="outline"
      className={cn("text-[10px] font-semibold uppercase tracking-wider no-default-hover-elevate no-default-active-elevate", config.className, className)}
      data-testid={`badge-severity-${severity}`}
    >
      {config.label}
    </Badge>
  );
}

const eventTypeLabels: Record<string, string> = {
  tool_call: "Tool Call",
  tool_response: "Tool Response",
  goal_drift: "Goal Drift",
  credential_detected: "Credential Detected",
  policy_violation: "Policy Violation",
  anomaly_detected: "Anomaly Detected",
  session_start: "Session Start",
  session_end: "Session End",
  server_untrusted: "Server Untrusted",
  behavioral_anomaly: "Behavioral Anomaly",
  trust_violation: "Trust Violation",
  tool_redefinition: "Tool Redefinition",
  agent_attested: "Agent Attested",
  command_injection: "Command Injection",
  path_traversal: "Path Traversal",
};

export function EventTypeBadge({ type, className }: { type: string; className?: string }) {
  const threatTypes = ["goal_drift", "credential_detected", "policy_violation", "command_injection", "path_traversal", "trust_violation", "tool_redefinition"];
  const warningTypes = ["anomaly_detected", "behavioral_anomaly", "server_untrusted"];
  const infoTypes = ["tool_call", "tool_response", "session_start", "session_end", "agent_attested"];

  let badgeClass = "bg-slate-500/10 text-slate-500 dark:text-slate-400 border-slate-500/20";
  if (threatTypes.includes(type)) {
    badgeClass = "bg-red-500/10 text-red-500 dark:text-red-400 border-red-500/20";
  } else if (warningTypes.includes(type)) {
    badgeClass = "bg-amber-500/10 text-amber-500 dark:text-amber-400 border-amber-500/20";
  } else if (infoTypes.includes(type)) {
    badgeClass = "bg-cyan-500/10 text-cyan-500 dark:text-cyan-400 border-cyan-500/20";
  }

  return (
    <Badge
      variant="outline"
      className={cn("text-[10px] font-medium no-default-hover-elevate no-default-active-elevate", badgeClass, className)}
      data-testid={`badge-event-type-${type}`}
    >
      {eventTypeLabels[type] || type}
    </Badge>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const isActive = status === "active" || status === "allowed";
  const isBlocked = status === "blocked";
  
  let badgeClass = "bg-slate-500/10 text-slate-500 dark:text-slate-400 border-slate-500/20";
  if (isActive) {
    badgeClass = "bg-emerald-500/10 text-emerald-500 dark:text-emerald-400 border-emerald-500/20";
  } else if (isBlocked) {
    badgeClass = "bg-red-500/10 text-red-500 dark:text-red-400 border-red-500/20";
  }

  return (
    <Badge
      variant="outline"
      className={cn("text-[10px] font-semibold uppercase tracking-wider no-default-hover-elevate no-default-active-elevate", badgeClass)}
      data-testid={`badge-status-${status}`}
    >
      {status}
    </Badge>
  );
}
