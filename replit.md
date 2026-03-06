# Aiglos Security Dashboard

## Overview
Full-stack web dashboard for the Aiglos AI Agent Security Runtime. Provides real-time monitoring, event logging, trust management, policy configuration, and CMMC compliance tracking for AI agents operating through MCP (Model Context Protocol) proxies.

## Architecture
- **Frontend**: React + TypeScript + Vite + Tailwind CSS + shadcn/ui
- **Backend**: Express.js + TypeScript
- **Database**: PostgreSQL with Drizzle ORM
- **Routing**: wouter (frontend), Express (backend API)
- **State**: TanStack React Query

## Key Pages
1. **Dashboard** (`/`) - Security overview with metrics, recent events, active sessions
2. **Sessions** (`/sessions`) - Agent session monitoring with integrity/anomaly scores
3. **Events** (`/events`) - Security event log with severity/type filtering
4. **Trust Registry** (`/trust`) - Manage trusted/blocked MCP servers
5. **Policies** (`/policies`) - Security policy rules with toggle/create
6. **Compliance** (`/compliance`) - CMMC/NIST control coverage visualization

## Data Models
- `sessions` - AI agent sessions with goal integrity and anomaly scores
- `securityEvents` - Security events (goal drift, credential detection, policy violations, etc.)
- `toolCalls` - MCP tool call audit log
- `trustedServers` - MCP server trust registry
- `policyRules` - Security policy rules

## Theme
- Dark-first cybersecurity theme with cyan primary (`hsl(199, 89%, 48%)`)
- Inter font family, JetBrains Mono for code
- Custom severity badge system (critical/high/medium/low/info)

## API Routes
All prefixed with `/api/`:
- `GET /dashboard/stats` - Aggregate dashboard metrics
- `GET /sessions` - List sessions (with `?active=true` filter)
- `GET /events` - List events with `?severity=` and `?type=` filters
- `GET/POST /trust` - Trust registry CRUD
- `PATCH /trust/:id` - Update server status
- `GET/POST /policies` - Policy rules CRUD
- `PATCH /policies/:id` - Toggle policy enabled state
- `GET /compliance` - CMMC compliance data
