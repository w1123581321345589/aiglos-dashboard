import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SeverityBadge, EventTypeBadge } from "@/components/severity-badge";
import { AlertTriangle, Filter, ShieldCheck } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import type { SecurityEvent } from "@shared/schema";
import { SEVERITIES, EVENT_TYPES } from "@shared/schema";

export default function Events() {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const queryParams = new URLSearchParams();
  if (severityFilter !== "all") queryParams.set("severity", severityFilter);
  if (typeFilter !== "all") queryParams.set("type", typeFilter);
  const qs = queryParams.toString();

  const { data: events, isLoading } = useQuery<SecurityEvent[]>({
    queryKey: ["/api/events", qs ? `?${qs}` : ""],
  });

  const clearFilters = () => {
    setSeverityFilter("all");
    setTypeFilter("all");
  };

  const hasFilters = severityFilter !== "all" || typeFilter !== "all";

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-semibold tracking-tight" data-testid="text-events-title">
            Security Events
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Real-time security event log with filtering and analysis
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-1.5">
          <Filter className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="text-xs text-muted-foreground">Filters:</span>
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[140px] h-8 text-xs" data-testid="select-severity-filter">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-[180px] h-8 text-xs" data-testid="select-type-filter">
            <SelectValue placeholder="Event Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            {EVENT_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {t.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {hasFilters && (
          <Button variant="ghost" size="sm" onClick={clearFilters} data-testid="button-clear-filters">
            Clear
          </Button>
        )}
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-3">
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} className="h-14 w-full" />
              ))}
            </div>
          ) : events && events.length > 0 ? (
            <div className="divide-y divide-border/50">
              {events.map((event) => (
                <EventRow key={event.id} event={event} />
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-16">
              <ShieldCheck className="w-12 h-12 text-muted-foreground/30 mb-4" />
              <p className="text-sm text-muted-foreground">
                {hasFilters ? "No events match the current filters" : "No security events recorded"}
              </p>
              <p className="text-xs text-muted-foreground/60 mt-1">
                {hasFilters ? "Try adjusting your filters" : "Events will appear when agents interact with MCP servers"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function EventRow({ event }: { event: SecurityEvent }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div data-testid={`event-detail-${event.id}`}>
      <div
        className="flex items-center gap-3 px-4 py-3 hover-elevate cursor-pointer"
        onClick={() => setExpanded(!expanded)}
        data-testid={`button-expand-event-${event.id}`}
      >
        <SeverityBadge severity={event.severity} />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate">{event.title}</p>
          <p className="text-xs text-muted-foreground truncate">
            {event.description}
          </p>
        </div>
        <EventTypeBadge type={event.eventType} />
        <span className="text-[10px] text-muted-foreground whitespace-nowrap flex-shrink-0 font-mono">
          {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
        </span>
      </div>
      {expanded && (
        <div className="px-4 pb-3">
          <div className="bg-muted/50 rounded-md p-3 space-y-2">
            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
              <div>
                <span className="text-muted-foreground">Session:</span>{" "}
                <span className="font-mono text-[11px]">{event.sessionId.slice(0, 12)}...</span>
              </div>
              <div>
                <span className="text-muted-foreground">Event ID:</span>{" "}
                <span className="font-mono text-[11px]">{event.id.slice(0, 12)}...</span>
              </div>
              {event.cmmcControls && event.cmmcControls.length > 0 && (
                <div className="col-span-2">
                  <span className="text-muted-foreground">CMMC Controls:</span>{" "}
                  <span className="font-mono text-[11px]">{event.cmmcControls.join(", ")}</span>
                </div>
              )}
              {event.nistControls && event.nistControls.length > 0 && (
                <div className="col-span-2">
                  <span className="text-muted-foreground">NIST Controls:</span>{" "}
                  <span className="font-mono text-[11px]">{event.nistControls.join(", ")}</span>
                </div>
              )}
            </div>
            {event.details && Object.keys(event.details as object).length > 0 && (
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Details</p>
                <pre className="text-[11px] font-mono bg-background/50 rounded p-2 overflow-x-auto">
                  {JSON.stringify(event.details, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
