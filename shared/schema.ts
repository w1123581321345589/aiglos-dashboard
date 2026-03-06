import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, real, boolean, jsonb, integer } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export const sessions = pgTable("sessions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  modelId: text("model_id").notNull(),
  modelVersion: text("model_version").notNull(),
  initiatedBy: text("initiated_by").notNull(),
  authorizedGoal: text("authorized_goal").notNull(),
  goalIntegrityScore: real("goal_integrity_score").notNull().default(1.0),
  anomalyScore: real("anomaly_score").notNull().default(0.0),
  isActive: boolean("is_active").notNull().default(true),
  toolPermissions: text("tool_permissions").array().default(sql`'{}'::text[]`),
  systemPromptHash: text("system_prompt_hash"),
  startTime: timestamp("start_time").notNull().defaultNow(),
  endTime: timestamp("end_time"),
});

export const insertSessionSchema = createInsertSchema(sessions).omit({ id: true });
export type InsertSession = z.infer<typeof insertSessionSchema>;
export type Session = typeof sessions.$inferSelect;

export const securityEvents = pgTable("security_events", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  sessionId: varchar("session_id").notNull(),
  eventType: text("event_type").notNull(),
  severity: text("severity").notNull(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  details: jsonb("details").default({}),
  cmmcControls: text("cmmc_controls").array().default(sql`'{}'::text[]`),
  nistControls: text("nist_controls").array().default(sql`'{}'::text[]`),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
});

export const insertSecurityEventSchema = createInsertSchema(securityEvents).omit({ id: true });
export type InsertSecurityEvent = z.infer<typeof insertSecurityEventSchema>;
export type SecurityEvent = typeof securityEvents.$inferSelect;

export const toolCalls = pgTable("tool_calls", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  sessionId: varchar("session_id").notNull(),
  serverId: text("server_id").notNull(),
  toolName: text("tool_name").notNull(),
  arguments: jsonb("arguments").default({}),
  allowed: boolean("allowed").notNull().default(true),
  blockedReason: text("blocked_reason"),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
});

export const insertToolCallSchema = createInsertSchema(toolCalls).omit({ id: true });
export type InsertToolCall = z.infer<typeof insertToolCallSchema>;
export type ToolCall = typeof toolCalls.$inferSelect;

export const trustedServers = pgTable("trusted_servers", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  host: text("host").notNull(),
  port: integer("port").notNull(),
  alias: text("alias"),
  status: text("status").notNull().default("allowed"),
  reason: text("reason"),
  toolManifestHash: text("tool_manifest_hash"),
  lastSeen: timestamp("last_seen").defaultNow(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertTrustedServerSchema = createInsertSchema(trustedServers).omit({ id: true });
export type InsertTrustedServer = z.infer<typeof insertTrustedServerSchema>;
export type TrustedServer = typeof trustedServers.$inferSelect;

export const policyRules = pgTable("policy_rules", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  description: text("description").notNull(),
  pattern: text("pattern").notNull(),
  action: text("action").notNull().default("block"),
  severity: text("severity").notNull().default("high"),
  enabled: boolean("enabled").notNull().default(true),
  category: text("category").notNull().default("general"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertPolicyRuleSchema = createInsertSchema(policyRules).omit({ id: true });
export type InsertPolicyRule = z.infer<typeof insertPolicyRuleSchema>;
export type PolicyRule = typeof policyRules.$inferSelect;

export const EVENT_TYPES = [
  "tool_call", "tool_response", "goal_drift", "credential_detected",
  "policy_violation", "anomaly_detected", "session_start", "session_end",
  "server_untrusted", "behavioral_anomaly", "trust_violation",
  "tool_redefinition", "agent_attested", "command_injection", "path_traversal"
] as const;

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export const POLICY_ACTIONS = ["allow", "block", "log", "alert", "require_approval"] as const;
