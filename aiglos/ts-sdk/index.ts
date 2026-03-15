/**
 * aiglos — AI agent security runtime for TypeScript/Node.js
 *
 * One import. Every agent action inspected before it runs.
 * MCP, HTTP/API, CLI, subprocess, agent spawns.
 *
 * @example
 * import aiglos from "aiglos";
 *
 * aiglos.attach({
 *   agentName:           "my-agent",
 *   policy:              "enterprise",
 *   interceptHttp:       true,
 *   allowHttp:           ["api.openai.com", "*.amazonaws.com"],
 *   interceptSubprocess: true,
 *   subprocessTier3Mode: "pause",
 * });
 *
 * // Inspect a command manually
 * const result = aiglos.check("rm -rf /var/data");
 * if (result.verdict === "BLOCK") throw new Error(result.reason);
 *
 * // Close session and get artifact
 * const artifact = aiglos.close();
 */

export * from "./types";
export * from "./http";
export * from "./subprocess";
export * from "./session";

import { AiglosConfig, SessionArtifact, SubprocScanResult, HttpScanResult } from "./types";
import { patchGlobalFetch } from "./http";
import { patchChildProcess, inspectCommand } from "./subprocess";
import { Session } from "./session";

let _session: Session | null = null;

/**
 * Attach Aiglos to the current process.
 * Optionally patches globalThis.fetch and/or child_process.
 */
export function attach(config: AiglosConfig = {}): Session {
  const {
    agentName          = "aiglos",
    policy             = "enterprise",
    interceptHttp      = false,
    allowHttp          = [],
    interceptSubprocess = false,
    subprocessTier3Mode = "warn",
    sessionId,
  } = config;

  _session = new Session({ agentName, policy, sessionId });

  if (interceptHttp) {
    patchGlobalFetch({
      allowHttp, policy,
      onBlock: r => _session?.recordHttpEvent(r),
      onWarn:  r => _session?.recordHttpEvent(r),
    });
  }

  if (interceptSubprocess) {
    patchChildProcess({
      tier3Mode: subprocessTier3Mode,
      onBlock: r => _session?.recordSubprocEvent(r),
      onWarn:  r => _session?.recordSubprocEvent(r),
    });
  }

  console.info(
    `[Aiglos v${VERSION}] Attached — agent=${agentName} policy=${policy} ` +
    `http=${interceptHttp ? "on" : "off"} subprocess=${interceptSubprocess ? "on" : "off"}`
  );

  return _session;
}

/**
 * Manually inspect a shell command. Returns a SubprocScanResult.
 */
export function check(cmd: string): SubprocScanResult {
  return inspectCommand(cmd, { mode: "block" });
}

/**
 * Close the current session and return the artifact.
 */
export function close(): SessionArtifact {
  if (!_session) {
    throw new Error("[Aiglos] No active session. Call attach() first.");
  }
  const artifact = _session.close();
  _session = null;
  return artifact;
}

/**
 * Return current runtime status.
 */
export function status() {
  return {
    version:       VERSION,
    sessionActive: _session !== null,
    agentName:     _session?.agentName ?? null,
  };
}

export const VERSION = "0.10.0";

export default { attach, check, close, status, VERSION };
