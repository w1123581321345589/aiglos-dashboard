import { db } from "./db";
import { sessions, securityEvents, toolCalls, trustedServers, policyRules } from "@shared/schema";
import { sql } from "drizzle-orm";

export async function seedDatabase() {
  const [existing] = await db.select({ count: sql<number>`count(*)` }).from(sessions);
  if (Number(existing.count) > 0) return;

  const sessionData = [
    {
      modelId: "claude-3.5-sonnet",
      modelVersion: "20241022",
      initiatedBy: "vscode-extension",
      authorizedGoal: "Refactor authentication module and implement OAuth2 flow with proper token rotation",
      goalIntegrityScore: 0.94,
      anomalyScore: 0.05,
      isActive: true,
      toolPermissions: ["read_file", "write_file", "execute_command", "search"],
      systemPromptHash: "a3f2c8d9e1b4a7f6c3d2e5f8a1b4c7d0",
      startTime: new Date(Date.now() - 45 * 60000),
    },
    {
      modelId: "gpt-4-turbo",
      modelVersion: "2024-04-09",
      initiatedBy: "cursor-ide",
      authorizedGoal: "Debug memory leak in WebSocket connection handler and optimize connection pooling",
      goalIntegrityScore: 0.72,
      anomalyScore: 0.28,
      isActive: true,
      toolPermissions: ["read_file", "write_file", "execute_command"],
      systemPromptHash: "b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9",
      startTime: new Date(Date.now() - 120 * 60000),
    },
    {
      modelId: "claude-3-opus",
      modelVersion: "20240229",
      initiatedBy: "automation-pipeline",
      authorizedGoal: "Generate API documentation and create integration tests for payment service",
      goalIntegrityScore: 0.98,
      anomalyScore: 0.02,
      isActive: false,
      toolPermissions: ["read_file", "write_file", "search"],
      systemPromptHash: "c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0",
      startTime: new Date(Date.now() - 6 * 3600000),
      endTime: new Date(Date.now() - 4 * 3600000),
    },
    {
      modelId: "gpt-4o",
      modelVersion: "2024-05-13",
      initiatedBy: "jetbrains-plugin",
      authorizedGoal: "Implement rate limiting middleware and DDoS protection for public API endpoints",
      goalIntegrityScore: 0.45,
      anomalyScore: 0.62,
      isActive: false,
      toolPermissions: ["read_file", "write_file", "execute_command", "network"],
      systemPromptHash: "d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1",
      startTime: new Date(Date.now() - 24 * 3600000),
      endTime: new Date(Date.now() - 22 * 3600000),
    },
    {
      modelId: "claude-3.5-sonnet",
      modelVersion: "20241022",
      initiatedBy: "ci-runner",
      authorizedGoal: "Scan codebase for hardcoded secrets and sensitive data exposure",
      goalIntegrityScore: 1.0,
      anomalyScore: 0.0,
      isActive: true,
      toolPermissions: ["read_file", "search"],
      systemPromptHash: "e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2",
      startTime: new Date(Date.now() - 15 * 60000),
    },
  ];

  const createdSessions = await db.insert(sessions).values(sessionData).returning();

  const eventData = [
    {
      sessionId: createdSessions[3].id,
      eventType: "goal_drift",
      severity: "critical",
      title: "Goal Drift Detected",
      description: "Agent deviated from rate limiting task to access internal credentials store",
      details: { driftScore: 0.45, originalGoal: "rate limiting", detectedActivity: "credential access" },
      cmmcControls: ["AC-3.1", "AU-2.1"],
      nistControls: ["AC-3", "AU-2"],
      timestamp: new Date(Date.now() - 23 * 3600000),
    },
    {
      sessionId: createdSessions[3].id,
      eventType: "credential_detected",
      severity: "critical",
      title: "AWS Access Key Detected in Tool Arguments",
      description: "AKIA-pattern AWS access key found in execute_command arguments",
      details: { pattern: "AKIA*", tool: "execute_command", redacted: true },
      cmmcControls: ["SC-28.1", "IA-5.1"],
      nistControls: ["SC-28", "IA-5"],
      timestamp: new Date(Date.now() - 22.5 * 3600000),
    },
    {
      sessionId: createdSessions[1].id,
      eventType: "anomaly_detected",
      severity: "high",
      title: "Unusual Tool Call Acceleration",
      description: "Tool call frequency increased 4x in the last 5 minutes",
      details: { normalRate: 2.1, currentRate: 8.7, window: "5m" },
      cmmcControls: ["AU-6.1", "CM-7.1"],
      nistControls: ["AU-6", "CM-7"],
      timestamp: new Date(Date.now() - 90 * 60000),
    },
    {
      sessionId: createdSessions[1].id,
      eventType: "policy_violation",
      severity: "high",
      title: "Blocked: sudo Command Execution",
      description: "Agent attempted to execute sudo command which is blocked by policy",
      details: { command: "sudo cat /etc/shadow", rule: "block_sudo", action: "block" },
      cmmcControls: ["AC-3.2", "CM-6.1"],
      nistControls: ["AC-3", "CM-6"],
      timestamp: new Date(Date.now() - 85 * 60000),
    },
    {
      sessionId: createdSessions[0].id,
      eventType: "tool_call",
      severity: "info",
      title: "File Read: auth/oauth2.ts",
      description: "Agent read authentication module source file",
      details: { tool: "read_file", path: "src/auth/oauth2.ts" },
      cmmcControls: ["AU-2.1"],
      nistControls: ["AU-2"],
      timestamp: new Date(Date.now() - 30 * 60000),
    },
    {
      sessionId: createdSessions[0].id,
      eventType: "agent_attested",
      severity: "info",
      title: "Agent Attestation Completed",
      description: "Session attestation document generated and signed",
      details: { algorithm: "RSA-2048", hash: "SHA-256" },
      cmmcControls: ["IA-2.1", "SC-13.1"],
      nistControls: ["IA-2", "SC-13"],
      timestamp: new Date(Date.now() - 44 * 60000),
    },
    {
      sessionId: createdSessions[4].id,
      eventType: "credential_detected",
      severity: "high",
      title: "GitHub Personal Access Token Found",
      description: "ghp_ pattern token detected in source file during scan",
      details: { pattern: "ghp_*", file: ".env.local", redacted: true },
      cmmcControls: ["SC-28.1", "IA-5.1", "CM-2.1"],
      nistControls: ["SC-28", "IA-5", "CM-2"],
      timestamp: new Date(Date.now() - 10 * 60000),
    },
    {
      sessionId: createdSessions[1].id,
      eventType: "behavioral_anomaly",
      severity: "medium",
      title: "Domain Shift: Network Operations",
      description: "Agent shifted from debugging to making external network requests",
      details: { originalDomain: "file_operations", newDomain: "network_operations" },
      cmmcControls: ["SC-7.1", "AU-6.1"],
      nistControls: ["SC-7", "AU-6"],
      timestamp: new Date(Date.now() - 100 * 60000),
    },
    {
      sessionId: createdSessions[2].id,
      eventType: "session_end",
      severity: "info",
      title: "Session Completed Successfully",
      description: "Agent session ended with high integrity score",
      details: { finalScore: 0.98, toolCalls: 47, duration: "2h 14m" },
      cmmcControls: ["AU-2.1"],
      nistControls: ["AU-2"],
      timestamp: new Date(Date.now() - 4 * 3600000),
    },
    {
      sessionId: createdSessions[3].id,
      eventType: "command_injection",
      severity: "critical",
      title: "Command Injection Attempt Blocked",
      description: "Detected shell metacharacter injection in tool arguments",
      details: { pattern: "; rm -rf /", tool: "execute_command", action: "blocked" },
      cmmcControls: ["AC-3.2", "SC-7.1", "CM-7.1"],
      nistControls: ["AC-3", "SC-7", "CM-7"],
      timestamp: new Date(Date.now() - 23.2 * 3600000),
    },
    {
      sessionId: createdSessions[0].id,
      eventType: "tool_call",
      severity: "info",
      title: "File Write: auth/token-rotation.ts",
      description: "Agent created token rotation implementation file",
      details: { tool: "write_file", path: "src/auth/token-rotation.ts", size: 2847 },
      cmmcControls: ["AU-3.1"],
      nistControls: ["AU-3"],
      timestamp: new Date(Date.now() - 20 * 60000),
    },
    {
      sessionId: createdSessions[4].id,
      eventType: "tool_call",
      severity: "low",
      title: "Search: Hardcoded Secrets Pattern",
      description: "Agent scanning for common secret patterns in codebase",
      details: { tool: "search", pattern: "(?i)(api_key|secret|password|token)\\s*=\\s*['\"]" },
      cmmcControls: ["AU-2.1", "SC-28.1"],
      nistControls: ["AU-2", "SC-28"],
      timestamp: new Date(Date.now() - 12 * 60000),
    },
  ];

  await db.insert(securityEvents).values(eventData);

  const toolCallData = [
    { sessionId: createdSessions[0].id, serverId: "localhost:18789", toolName: "read_file", arguments: { path: "src/auth/oauth2.ts" }, allowed: true, timestamp: new Date(Date.now() - 30 * 60000) },
    { sessionId: createdSessions[0].id, serverId: "localhost:18789", toolName: "write_file", arguments: { path: "src/auth/token-rotation.ts" }, allowed: true, timestamp: new Date(Date.now() - 20 * 60000) },
    { sessionId: createdSessions[1].id, serverId: "localhost:18789", toolName: "execute_command", arguments: { command: "sudo cat /etc/shadow" }, allowed: false, blockedReason: "Policy: block_sudo", timestamp: new Date(Date.now() - 85 * 60000) },
    { sessionId: createdSessions[1].id, serverId: "localhost:18789", toolName: "read_file", arguments: { path: "src/ws/connection.ts" }, allowed: true, timestamp: new Date(Date.now() - 115 * 60000) },
    { sessionId: createdSessions[3].id, serverId: "localhost:18789", toolName: "execute_command", arguments: { command: "[REDACTED]; rm -rf /" }, allowed: false, blockedReason: "Command injection detected", timestamp: new Date(Date.now() - 23.2 * 3600000) },
    { sessionId: createdSessions[4].id, serverId: "localhost:18789", toolName: "search", arguments: { pattern: "api_key|secret" }, allowed: true, timestamp: new Date(Date.now() - 12 * 60000) },
  ];

  await db.insert(toolCalls).values(toolCallData);

  const serverData = [
    { host: "localhost", port: 18789, alias: "dev-server", status: "allowed", reason: "Local development MCP server", toolManifestHash: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", lastSeen: new Date(Date.now() - 5 * 60000) },
    { host: "mcp.internal.corp", port: 443, alias: "corp-mcp", status: "allowed", reason: "Internal corporate MCP server", toolManifestHash: "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7", lastSeen: new Date(Date.now() - 2 * 3600000) },
    { host: "evil-mcp.example.com", port: 443, alias: "blocked-exfil", status: "blocked", reason: "Known data exfiltration endpoint", toolManifestHash: null, lastSeen: null },
    { host: "staging-mcp.internal.corp", port: 8765, alias: "staging", status: "audit", reason: "Staging environment - audit mode", toolManifestHash: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8", lastSeen: new Date(Date.now() - 12 * 3600000) },
  ];

  await db.insert(trustedServers).values(serverData);

  const policyData = [
    { name: "Block sudo commands", description: "Prevents execution of any command using sudo or su escalation", pattern: "*sudo*|*su -*", action: "block", severity: "critical", enabled: true, category: "command_control" },
    { name: "Block rm -rf", description: "Prevents recursive force deletion commands that could destroy filesystems", pattern: "*rm -rf*|*rm -fr*", action: "block", severity: "critical", enabled: true, category: "command_control" },
    { name: "Block path traversal", description: "Detects and blocks directory traversal attempts in file operations", pattern: "*../*|*..\\\\*", action: "block", severity: "high", enabled: true, category: "file_security" },
    { name: "Alert on .env access", description: "Generates alert when agent reads environment variable files", pattern: "*.env*|*.secret*", action: "alert", severity: "high", enabled: true, category: "credential_protection" },
    { name: "Log SSH key access", description: "Logs any attempt to access SSH private keys", pattern: "*id_rsa*|*id_ed25519*|*.pem", action: "log", severity: "medium", enabled: true, category: "credential_protection" },
    { name: "Block curl to external", description: "Blocks outbound HTTP requests to non-allowlisted domains", pattern: "*curl *|*wget *|*http.get*", action: "alert", severity: "medium", enabled: false, category: "network_security" },
    { name: "Block eval/exec", description: "Prevents dynamic code evaluation which could enable injection attacks", pattern: "*eval(*|*exec(*|*Function(*", action: "block", severity: "high", enabled: true, category: "code_safety" },
  ];

  await db.insert(policyRules).values(policyData);

  console.log("Database seeded with demo data");
}
