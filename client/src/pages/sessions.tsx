import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusBadge } from "@/components/severity-badge";
import { Activity, Clock, Target, User } from "lucide-react";
import { formatDistanceToNow, format } from "date-fns";
import type { Session } from "@shared/schema";
import { cn } from "@/lib/utils";

export default function Sessions() {
  const { data: sessions, isLoading } = useQuery<Session[]>({
    queryKey: ["/api/sessions"],
  });

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div>
        <h2 className="text-xl font-semibold tracking-tight" data-testid="text-sessions-title">
          Agent Sessions
        </h2>
        <p className="text-sm text-muted-foreground mt-1">
          Monitor and inspect AI agent sessions with integrity scoring
        </p>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-5">
                <Skeleton className="h-6 w-40 mb-3" />
                <Skeleton className="h-4 w-full mb-2" />
                <Skeleton className="h-4 w-3/4" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : sessions && sessions.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {sessions.map((session) => (
            <SessionCard key={session.id} session={session} />
          ))}
        </div>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Activity className="w-12 h-12 text-muted-foreground/30 mb-4" />
            <p className="text-sm text-muted-foreground">No sessions recorded yet</p>
            <p className="text-xs text-muted-foreground/60 mt-1">
              Sessions appear when AI agents connect through the proxy
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function SessionCard({ session }: { session: Session }) {
  const integrityPercent = Math.round(session.goalIntegrityScore * 100);
  const anomalyPercent = Math.round(session.anomalyScore * 100);

  let integrityColor = "text-emerald-500";
  let integrityBg = "bg-emerald-500";
  if (integrityPercent < 50) {
    integrityColor = "text-red-500";
    integrityBg = "bg-red-500";
  } else if (integrityPercent < 75) {
    integrityColor = "text-amber-500";
    integrityBg = "bg-amber-500";
  }

  return (
    <Card className="hover-elevate" data-testid={`card-session-${session.id}`}>
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <CardTitle className="text-sm font-semibold truncate">
              {session.modelId}
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              {session.modelVersion}
            </p>
          </div>
          <StatusBadge status={session.isActive ? "active" : "ended"} />
        </div>
      </CardHeader>
      <CardContent className="space-y-4 pt-0">
        <div className="flex items-start gap-2">
          <Target className="w-3.5 h-3.5 text-muted-foreground mt-0.5 flex-shrink-0" />
          <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2">
            {session.authorizedGoal}
          </p>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">
              Goal Integrity
            </p>
            <div className="flex items-center gap-2">
              <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                <div
                  className={cn("h-full rounded-full transition-all", integrityBg)}
                  style={{ width: `${integrityPercent}%` }}
                />
              </div>
              <span className={cn("text-xs font-mono font-semibold", integrityColor)}>
                {integrityPercent}%
              </span>
            </div>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">
              Anomaly Score
            </p>
            <div className="flex items-center gap-2">
              <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                <div
                  className={cn(
                    "h-full rounded-full transition-all",
                    anomalyPercent > 50 ? "bg-red-500" : anomalyPercent > 25 ? "bg-amber-500" : "bg-emerald-500"
                  )}
                  style={{ width: `${Math.max(anomalyPercent, 3)}%` }}
                />
              </div>
              <span className={cn(
                "text-xs font-mono font-semibold",
                anomalyPercent > 50 ? "text-red-500" : anomalyPercent > 25 ? "text-amber-500" : "text-emerald-500"
              )}>
                {anomalyPercent}%
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 pt-1 border-t border-border/50 flex-wrap">
          <div className="flex items-center gap-1.5">
            <User className="w-3 h-3 text-muted-foreground" />
            <span className="text-[11px] text-muted-foreground">{session.initiatedBy}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Clock className="w-3 h-3 text-muted-foreground" />
            <span className="text-[11px] text-muted-foreground">
              {formatDistanceToNow(new Date(session.startTime), { addSuffix: true })}
            </span>
          </div>
          {session.toolPermissions && session.toolPermissions.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              {session.toolPermissions.slice(0, 3).map((perm) => (
                <Badge
                  key={perm}
                  variant="secondary"
                  className="text-[9px] no-default-hover-elevate no-default-active-elevate"
                >
                  {perm}
                </Badge>
              ))}
              {session.toolPermissions.length > 3 && (
                <Badge variant="secondary" className="text-[9px] no-default-hover-elevate no-default-active-elevate">
                  +{session.toolPermissions.length - 3}
                </Badge>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
