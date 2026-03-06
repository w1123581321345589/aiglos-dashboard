import {
  type User, type InsertUser,
  type Session, type InsertSession,
  type SecurityEvent, type InsertSecurityEvent,
  type ToolCall, type InsertToolCall,
  type TrustedServer, type InsertTrustedServer,
  type PolicyRule, type InsertPolicyRule,
  users, sessions, securityEvents, toolCalls, trustedServers, policyRules,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, sql, count } from "drizzle-orm";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;

  getSessions(activeOnly?: boolean): Promise<Session[]>;
  getSession(id: string): Promise<Session | undefined>;
  createSession(session: InsertSession): Promise<Session>;

  getSecurityEvents(filters?: { severity?: string; type?: string; limit?: number }): Promise<SecurityEvent[]>;
  createSecurityEvent(event: InsertSecurityEvent): Promise<SecurityEvent>;

  getToolCalls(sessionId?: string): Promise<ToolCall[]>;
  createToolCall(call: InsertToolCall): Promise<ToolCall>;

  getTrustedServers(): Promise<TrustedServer[]>;
  createTrustedServer(server: InsertTrustedServer): Promise<TrustedServer>;
  updateTrustedServer(id: string, data: Partial<TrustedServer>): Promise<TrustedServer | undefined>;

  getPolicyRules(): Promise<PolicyRule[]>;
  createPolicyRule(rule: InsertPolicyRule): Promise<PolicyRule>;
  updatePolicyRule(id: string, data: Partial<PolicyRule>): Promise<PolicyRule | undefined>;

  getDashboardStats(): Promise<{
    activeSessions: number;
    totalEvents: number;
    criticalEvents: number;
    blockedCalls: number;
    avgIntegrity: number;
    trustedServers: number;
  }>;

  getComplianceData(): Promise<{
    overallScore: number;
    controlFamilies: { id: string; name: string; controls: number; covered: number; score: number }[];
    recentControls: { id: string; name: string; status: string; eventsCount: number }[];
  }>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }

  async getSessions(activeOnly?: boolean): Promise<Session[]> {
    if (activeOnly) {
      return db.select().from(sessions).where(eq(sessions.isActive, true)).orderBy(desc(sessions.startTime));
    }
    return db.select().from(sessions).orderBy(desc(sessions.startTime));
  }

  async getSession(id: string): Promise<Session | undefined> {
    const [session] = await db.select().from(sessions).where(eq(sessions.id, id));
    return session;
  }

  async createSession(session: InsertSession): Promise<Session> {
    const [created] = await db.insert(sessions).values(session).returning();
    return created;
  }

  async getSecurityEvents(filters?: { severity?: string; type?: string; limit?: number }): Promise<SecurityEvent[]> {
    const conditions = [];
    if (filters?.severity) conditions.push(eq(securityEvents.severity, filters.severity));
    if (filters?.type) conditions.push(eq(securityEvents.eventType, filters.type));

    const query = db.select().from(securityEvents);
    if (conditions.length > 0) {
      return query.where(and(...conditions)).orderBy(desc(securityEvents.timestamp)).limit(filters?.limit || 100);
    }
    return query.orderBy(desc(securityEvents.timestamp)).limit(filters?.limit || 100);
  }

  async createSecurityEvent(event: InsertSecurityEvent): Promise<SecurityEvent> {
    const [created] = await db.insert(securityEvents).values(event).returning();
    return created;
  }

  async getToolCalls(sessionId?: string): Promise<ToolCall[]> {
    if (sessionId) {
      return db.select().from(toolCalls).where(eq(toolCalls.sessionId, sessionId)).orderBy(desc(toolCalls.timestamp));
    }
    return db.select().from(toolCalls).orderBy(desc(toolCalls.timestamp)).limit(100);
  }

  async createToolCall(call: InsertToolCall): Promise<ToolCall> {
    const [created] = await db.insert(toolCalls).values(call).returning();
    return created;
  }

  async getTrustedServers(): Promise<TrustedServer[]> {
    return db.select().from(trustedServers).orderBy(desc(trustedServers.createdAt));
  }

  async createTrustedServer(server: InsertTrustedServer): Promise<TrustedServer> {
    const [created] = await db.insert(trustedServers).values(server).returning();
    return created;
  }

  async updateTrustedServer(id: string, data: Partial<TrustedServer>): Promise<TrustedServer | undefined> {
    const [updated] = await db.update(trustedServers).set(data).where(eq(trustedServers.id, id)).returning();
    return updated;
  }

  async getPolicyRules(): Promise<PolicyRule[]> {
    return db.select().from(policyRules).orderBy(desc(policyRules.createdAt));
  }

  async createPolicyRule(rule: InsertPolicyRule): Promise<PolicyRule> {
    const [created] = await db.insert(policyRules).values(rule).returning();
    return created;
  }

  async updatePolicyRule(id: string, data: Partial<PolicyRule>): Promise<PolicyRule | undefined> {
    const [updated] = await db.update(policyRules).set(data).where(eq(policyRules.id, id)).returning();
    return updated;
  }

  async getDashboardStats() {
    const [activeCount] = await db.select({ count: count() }).from(sessions).where(eq(sessions.isActive, true));
    const [totalEventsCount] = await db.select({ count: count() }).from(securityEvents);
    const [criticalCount] = await db.select({ count: count() }).from(securityEvents).where(eq(securityEvents.severity, "critical"));
    const [blockedCount] = await db.select({ count: count() }).from(toolCalls).where(eq(toolCalls.allowed, false));
    const [avgResult] = await db.select({ avg: sql<number>`coalesce(avg(${sessions.goalIntegrityScore}), 1.0)` }).from(sessions);
    const [serverCount] = await db.select({ count: count() }).from(trustedServers).where(eq(trustedServers.status, "allowed"));

    return {
      activeSessions: activeCount.count,
      totalEvents: totalEventsCount.count,
      criticalEvents: criticalCount.count,
      blockedCalls: blockedCount.count,
      avgIntegrity: Number(avgResult.avg),
      trustedServers: serverCount.count,
    };
  }

  async getComplianceData() {
    const allEvents = await db.select().from(securityEvents);

    const controlMap = new Map<string, Set<string>>();
    for (const event of allEvents) {
      if (event.cmmcControls) {
        for (const ctrl of event.cmmcControls) {
          if (!controlMap.has(ctrl)) controlMap.set(ctrl, new Set());
          controlMap.get(ctrl)!.add(event.id);
        }
      }
    }

    const families = [
      { id: "AC", name: "Access Control", controls: 22 },
      { id: "AU", name: "Audit & Accountability", controls: 9 },
      { id: "CM", name: "Configuration Management", controls: 9 },
      { id: "IA", name: "Identification & Authentication", controls: 11 },
      { id: "SC", name: "System & Communications Protection", controls: 16 },
    ];

    const controlFamilies = families.map((f) => {
      const coveredControls = Array.from(controlMap.keys()).filter(k => k.startsWith(f.id)).length;
      const score = Math.round((coveredControls / f.controls) * 100);
      return { ...f, covered: coveredControls, score: Math.min(score, 100) };
    });

    const overallTotal = families.reduce((s, f) => s + f.controls, 0);
    const overallCovered = controlFamilies.reduce((s, f) => s + f.covered, 0);
    const overallScore = Math.round((overallCovered / overallTotal) * 100);

    const nistControls = [
      { id: "AC-3.1", name: "Account Management" },
      { id: "AC-3.2", name: "Access Enforcement" },
      { id: "AC-17.1", name: "Remote Access" },
      { id: "AU-2.1", name: "Event Logging" },
      { id: "AU-3.1", name: "Content of Audit Records" },
      { id: "AU-6.1", name: "Audit Review, Analysis, Reporting" },
      { id: "CM-2.1", name: "Baseline Configuration" },
      { id: "CM-6.1", name: "Configuration Settings" },
      { id: "CM-7.1", name: "Least Functionality" },
      { id: "IA-2.1", name: "Identification and Authentication" },
      { id: "IA-5.1", name: "Authenticator Management" },
      { id: "SC-7.1", name: "Boundary Protection" },
      { id: "SC-8.1", name: "Transmission Confidentiality" },
      { id: "SC-13.1", name: "Cryptographic Protection" },
      { id: "SC-28.1", name: "Protection of Information at Rest" },
    ];

    const recentControls = nistControls.map(c => {
      const eventCount = controlMap.get(c.id)?.size || 0;
      return {
        id: c.id,
        name: c.name,
        status: eventCount > 2 ? "covered" : eventCount > 0 ? "partial" : "not_covered",
        eventsCount: eventCount,
      };
    });

    return { overallScore, controlFamilies, recentControls };
  }
}

export const storage = new DatabaseStorage();
