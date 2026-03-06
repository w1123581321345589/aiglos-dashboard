import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: { value: number; label: string };
  variant?: "default" | "danger" | "warning" | "success";
  testId?: string;
}

const variantStyles = {
  default: "text-primary",
  danger: "text-red-500 dark:text-red-400",
  warning: "text-amber-500 dark:text-amber-400",
  success: "text-emerald-500 dark:text-emerald-400",
};

const variantBg = {
  default: "bg-primary/10",
  danger: "bg-red-500/10",
  warning: "bg-amber-500/10",
  success: "bg-emerald-500/10",
};

export function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  variant = "default",
  testId,
}: MetricCardProps) {
  return (
    <Card className="hover-elevate" data-testid={testId}>
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-1">
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-muted-foreground mb-1" data-testid={`${testId}-title`}>
              {title}
            </p>
            <p className="text-2xl font-bold tracking-tight" data-testid={`${testId}-value`}>
              {value}
            </p>
            {subtitle && (
              <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>
            )}
            {trend && (
              <p className={cn("text-xs mt-1 font-medium", trend.value >= 0 ? "text-emerald-500" : "text-red-500")}>
                {trend.value >= 0 ? "+" : ""}{trend.value}% {trend.label}
              </p>
            )}
          </div>
          <div className={cn("w-9 h-9 rounded-md flex items-center justify-center flex-shrink-0", variantBg[variant])}>
            <Icon className={cn("w-4 h-4", variantStyles[variant])} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
