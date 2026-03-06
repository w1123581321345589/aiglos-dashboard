import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { FileCheck, Shield, CheckCircle2, AlertCircle, Minus } from "lucide-react";
import { cn } from "@/lib/utils";

interface ComplianceData {
  overallScore: number;
  controlFamilies: {
    id: string;
    name: string;
    controls: number;
    covered: number;
    score: number;
  }[];
  recentControls: {
    id: string;
    name: string;
    status: "covered" | "partial" | "not_covered";
    eventsCount: number;
  }[];
}

export default function Compliance() {
  const { data, isLoading } = useQuery<ComplianceData>({
    queryKey: ["/api/compliance"],
  });

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div>
        <h2 className="text-xl font-semibold tracking-tight" data-testid="text-compliance-title">
          CMMC Compliance
        </h2>
        <p className="text-sm text-muted-foreground mt-1">
          NIST SP 800-171 Rev 2 control coverage mapped from security events
        </p>
      </div>

      {isLoading ? (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {Array.from({ length: 3 }).map((_, i) => (
              <Card key={i}><CardContent className="p-5"><Skeleton className="h-24 w-full" /></CardContent></Card>
            ))}
          </div>
        </div>
      ) : data ? (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="md:col-span-1">
              <CardContent className="p-6 flex flex-col items-center justify-center">
                <div className="relative w-28 h-28 mb-3">
                  <svg className="w-28 h-28 -rotate-90" viewBox="0 0 120 120">
                    <circle
                      cx="60" cy="60" r="52"
                      fill="none"
                      stroke="hsl(var(--muted))"
                      strokeWidth="8"
                    />
                    <circle
                      cx="60" cy="60" r="52"
                      fill="none"
                      stroke="hsl(var(--primary))"
                      strokeWidth="8"
                      strokeLinecap="round"
                      strokeDasharray={`${data.overallScore * 3.267} ${326.7 - data.overallScore * 3.267}`}
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-2xl font-bold" data-testid="text-compliance-score">
                      {data.overallScore}%
                    </span>
                  </div>
                </div>
                <p className="text-sm font-medium">Overall Coverage</p>
                <p className="text-xs text-muted-foreground mt-0.5">NIST 800-171 Controls</p>
              </CardContent>
            </Card>

            <Card className="md:col-span-2">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Control Families</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {data.controlFamilies.map((family) => (
                  <div key={family.id} data-testid={`compliance-family-${family.id}`}>
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-xs font-mono font-semibold text-primary flex-shrink-0">
                          {family.id}
                        </span>
                        <span className="text-xs truncate">{family.name}</span>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <span className="text-[10px] text-muted-foreground">
                          {family.covered}/{family.controls}
                        </span>
                        <span className={cn(
                          "text-xs font-semibold font-mono",
                          family.score >= 80 ? "text-emerald-500" : family.score >= 50 ? "text-amber-500" : "text-red-500"
                        )}>
                          {family.score}%
                        </span>
                      </div>
                    </div>
                    <Progress
                      value={family.score}
                      className="h-1.5"
                    />
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Individual Controls</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {data.recentControls.map((control) => (
                  <div
                    key={control.id}
                    className="flex items-center gap-3 p-2.5 rounded-md border border-border/50 hover-elevate"
                    data-testid={`control-${control.id}`}
                  >
                    {control.status === "covered" ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-500 flex-shrink-0" />
                    ) : control.status === "partial" ? (
                      <AlertCircle className="w-4 h-4 text-amber-500 flex-shrink-0" />
                    ) : (
                      <Minus className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                    )}
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-mono font-semibold">{control.id}</p>
                      <p className="text-[10px] text-muted-foreground truncate">{control.name}</p>
                    </div>
                    {control.eventsCount > 0 && (
                      <Badge variant="secondary" className="text-[9px] no-default-hover-elevate no-default-active-elevate">
                        {control.eventsCount}
                      </Badge>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <FileCheck className="w-12 h-12 text-muted-foreground/30 mb-4" />
            <p className="text-sm text-muted-foreground">No compliance data available</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
