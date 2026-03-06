import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MetricCard } from "@/components/metric-card";
import { SeverityBadge, EventTypeBadge } from "@/components/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Shield,
  Activity,
  AlertTriangle,
  ShieldCheck,
  Server,
  Zap,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import type { SecurityEvent, Session } from "@shared/schema";

interface DashboardStats {
  activeSessions: number;
  totalEvents: number;
  criticalEvents: number;
  blockedCalls: number;
  avgIntegrity: number;
  trustedServers: number;
}

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useQuery<DashboardStats>({
    queryKey: ["/api/dashboard/stats"],
  });

  const { data: recentEvents, isLoading: eventsLoading } = useQuery<SecurityEvent[]>({
    queryKey: ["/api/events", "?limit=8"],
  });

  const { data: activeSessions, isLoading: sessionsLoading } = useQuery<Session[]>({
    queryKey: ["/api/sessions", "?active=true"],
  });

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div>
        <h2 className="text-xl font-semibold tracking-tight" data-testid="text-dashboard-title">
          Security Overview
        </h2>
        <p className="text-sm text-muted-foreground mt-1">
          Real-time monitoring of AI agent security posture
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {statsLoading ? (
          Array.from({ length: 6 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-5">
                <Skeleton className="h-4 w-20 mb-2" />
                <Skeleton className="h-8 w-16" />
              </CardContent>
            </Card>
          ))
        ) : (
          <>
            <MetricCard
              title="Active Sessions"
              value={stats?.activeSessions ?? 0}
              icon={Activity}
              variant="success"
              testId="metric-active-sessions"
            />
            <MetricCard
              title="Total Events"
              value={stats?.totalEvents ?? 0}
              icon={Zap}
              testId="metric-total-events"
            />
            <MetricCard
              title="Critical Alerts"
              value={stats?.criticalEvents ?? 0}
              icon={AlertTriangle}
              variant={
                (stats?.criticalEvents ?? 0) > 0 ? "danger" : "success"
              }
              testId="metric-critical"
            />
            <MetricCard
              title="Blocked Calls"
              value={stats?.blockedCalls ?? 0}
              icon={Shield}
              variant={
                (stats?.blockedCalls ?? 0) > 0 ? "warning" : "success"
              }
              testId="metric-blocked"
            />
            <MetricCard
              title="Avg Integrity"
              value={
                stats?.avgIntegrity !== undefined
                  ? `${(stats.avgIntegrity * 100).toFixed(0)}%`
                  : "N/A"
              }
              icon={ShieldCheck}
              variant={
                (stats?.avgIntegrity ?? 1) < 0.7 ? "danger" : "success"
              }
              testId="metric-integrity"
            />
            <MetricCard
              title="Trusted Servers"
              value={stats?.trustedServers ?? 0}
              icon={Server}
              testId="metric-servers"
            />
          </>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        <Card className="lg:col-span-3">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Recent Security Events</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            {eventsLoading ? (
              <div className="space-y-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-12 w-full" />
                ))}
              </div>
            ) : recentEvents && recentEvents.length > 0 ? (
              <div className="space-y-1">
                {recentEvents.map((event) => (
                  <div
                    key={event.id}
                    className="flex items-center gap-3 p-2.5 rounded-md hover-elevate cursor-default"
                    data-testid={`event-row-${event.id}`}
                  >
                    <SeverityBadge severity={event.severity} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{event.title}</p>
                      <p className="text-xs text-muted-foreground truncate">
                        {event.description}
                      </p>
                    </div>
                    <EventTypeBadge type={event.eventType} />
                    <span className="text-[10px] text-muted-foreground whitespace-nowrap flex-shrink-0">
                      {formatDistanceToNow(new Date(event.timestamp), {
                        addSuffix: true,
                      })}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <ShieldCheck className="w-10 h-10 text-muted-foreground/40 mb-3" />
                <p className="text-sm text-muted-foreground">No security events recorded</p>
                <p className="text-xs text-muted-foreground/60 mt-1">
                  Events will appear here when agents connect
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Active Sessions</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            {sessionsLoading ? (
              <div className="space-y-3">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={i} className="h-16 w-full" />
                ))}
              </div>
            ) : activeSessions && activeSessions.length > 0 ? (
              <div className="space-y-2">
                {activeSessions.map((session) => (
                  <div
                    key={session.id}
                    className="p-3 rounded-md border border-border/50 hover-elevate"
                    data-testid={`session-card-${session.id}`}
                  >
                    <div className="flex items-center justify-between gap-1 mb-1.5">
                      <span className="text-sm font-medium truncate">
                        {session.modelId}
                      </span>
                      <IntegrityIndicator score={session.goalIntegrityScore} />
                    </div>
                    <p className="text-xs text-muted-foreground truncate mb-1">
                      {session.authorizedGoal}
                    </p>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] text-muted-foreground">
                        by {session.initiatedBy}
                      </span>
                      <span className="text-[10px] text-muted-foreground">
                        {formatDistanceToNow(new Date(session.startTime), {
                          addSuffix: true,
                        })}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <Activity className="w-10 h-10 text-muted-foreground/40 mb-3" />
                <p className="text-sm text-muted-foreground">No active sessions</p>
                <p className="text-xs text-muted-foreground/60 mt-1">
                  Sessions will appear when agents connect
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function IntegrityIndicator({ score }: { score: number }) {
  const percentage = Math.round(score * 100);
  let color = "text-emerald-500";
  let bgColor = "bg-emerald-500";
  if (percentage < 50) {
    color = "text-red-500";
    bgColor = "bg-red-500";
  } else if (percentage < 75) {
    color = "text-amber-500";
    bgColor = "bg-amber-500";
  }

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${bgColor}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span className={`text-xs font-mono font-medium ${color}`}>
        {percentage}%
      </span>
    </div>
  );
}
