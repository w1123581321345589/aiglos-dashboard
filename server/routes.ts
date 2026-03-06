import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertTrustedServerSchema, insertPolicyRuleSchema } from "@shared/schema";
import { z } from "zod";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  app.get("/api/dashboard/stats", async (_req, res) => {
    const stats = await storage.getDashboardStats();
    res.json(stats);
  });

  app.get("/api/sessions", async (req, res) => {
    const activeOnly = req.query.active === "true";
    const result = await storage.getSessions(activeOnly);
    res.json(result);
  });

  app.get("/api/sessions/:id", async (req, res) => {
    const session = await storage.getSession(req.params.id);
    if (!session) return res.status(404).json({ message: "Session not found" });
    res.json(session);
  });

  app.get("/api/events", async (req, res) => {
    const filters: { severity?: string; type?: string; limit?: number } = {};
    if (req.query.severity) filters.severity = req.query.severity as string;
    if (req.query.type) filters.type = req.query.type as string;
    if (req.query.limit) filters.limit = parseInt(req.query.limit as string);
    const result = await storage.getSecurityEvents(filters);
    res.json(result);
  });

  app.get("/api/trust", async (_req, res) => {
    const servers = await storage.getTrustedServers();
    res.json(servers);
  });

  app.post("/api/trust", async (req, res) => {
    const parsed = insertTrustedServerSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });
    const server = await storage.createTrustedServer(parsed.data);
    res.status(201).json(server);
  });

  app.patch("/api/trust/:id", async (req, res) => {
    const updated = await storage.updateTrustedServer(req.params.id, req.body);
    if (!updated) return res.status(404).json({ message: "Server not found" });
    res.json(updated);
  });

  app.get("/api/policies", async (_req, res) => {
    const policies = await storage.getPolicyRules();
    res.json(policies);
  });

  app.post("/api/policies", async (req, res) => {
    const parsed = insertPolicyRuleSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: parsed.error.message });
    const policy = await storage.createPolicyRule(parsed.data);
    res.status(201).json(policy);
  });

  app.patch("/api/policies/:id", async (req, res) => {
    const updated = await storage.updatePolicyRule(req.params.id, req.body);
    if (!updated) return res.status(404).json({ message: "Policy not found" });
    res.json(updated);
  });

  app.get("/api/compliance", async (_req, res) => {
    const data = await storage.getComplianceData();
    res.json(data);
  });

  return httpServer;
}
