import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useForm } from "react-hook-form";
import { Form, FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form";
import { ScrollText, Plus, ShieldAlert } from "lucide-react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { PolicyRule } from "@shared/schema";
import { SEVERITIES, POLICY_ACTIONS } from "@shared/schema";

export default function Policies() {
  const [open, setOpen] = useState(false);
  const { toast } = useToast();

  const { data: policies, isLoading } = useQuery<PolicyRule[]>({
    queryKey: ["/api/policies"],
  });

  const form = useForm({
    defaultValues: {
      name: "",
      description: "",
      pattern: "",
      action: "block",
      severity: "high",
      category: "general",
      enabled: true,
    },
  });

  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      await apiRequest("POST", "/api/policies", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policies"] });
      setOpen(false);
      form.reset();
      toast({ title: "Policy rule created" });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      await apiRequest("PATCH", `/api/policies/${id}`, { enabled });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policies"] });
    },
  });

  const actionColors: Record<string, string> = {
    block: "bg-red-500/10 text-red-500 dark:text-red-400 border-red-500/20",
    alert: "bg-amber-500/10 text-amber-500 dark:text-amber-400 border-amber-500/20",
    log: "bg-blue-500/10 text-blue-500 dark:text-blue-400 border-blue-500/20",
    allow: "bg-emerald-500/10 text-emerald-500 dark:text-emerald-400 border-emerald-500/20",
    require_approval: "bg-purple-500/10 text-purple-500 dark:text-purple-400 border-purple-500/20",
  };

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-semibold tracking-tight" data-testid="text-policies-title">
            Security Policies
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Define rules to control agent behavior and tool access
          </p>
        </div>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button size="sm" data-testid="button-add-policy">
              <Plus className="w-3.5 h-3.5 mr-1.5" />
              Add Rule
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>Create Policy Rule</DialogTitle>
            </DialogHeader>
            <Form {...form}>
              <form
                onSubmit={form.handleSubmit((data) => createMutation.mutate(data))}
                className="space-y-4"
              >
                <FormField control={form.control} name="name" render={({ field }) => (
                  <FormItem>
                    <FormLabel>Name</FormLabel>
                    <FormControl><Input placeholder="Block sudo commands" {...field} data-testid="input-policy-name" /></FormControl>
                  </FormItem>
                )} />
                <FormField control={form.control} name="description" render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description</FormLabel>
                    <FormControl><Textarea placeholder="Prevents execution of..." {...field} className="resize-none" data-testid="input-policy-desc" /></FormControl>
                  </FormItem>
                )} />
                <FormField control={form.control} name="pattern" render={({ field }) => (
                  <FormItem>
                    <FormLabel>Pattern (glob)</FormLabel>
                    <FormControl><Input placeholder="*sudo*" className="font-mono text-sm" {...field} data-testid="input-policy-pattern" /></FormControl>
                  </FormItem>
                )} />
                <div className="grid grid-cols-2 gap-3">
                  <FormField control={form.control} name="action" render={({ field }) => (
                    <FormItem>
                      <FormLabel>Action</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl><SelectTrigger data-testid="select-policy-action"><SelectValue /></SelectTrigger></FormControl>
                        <SelectContent>
                          {POLICY_ACTIONS.map((a) => (
                            <SelectItem key={a} value={a}>{a.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </FormItem>
                  )} />
                  <FormField control={form.control} name="severity" render={({ field }) => (
                    <FormItem>
                      <FormLabel>Severity</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl><SelectTrigger data-testid="select-policy-severity"><SelectValue /></SelectTrigger></FormControl>
                        <SelectContent>
                          {SEVERITIES.map((s) => (
                            <SelectItem key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </FormItem>
                  )} />
                </div>
                <FormField control={form.control} name="category" render={({ field }) => (
                  <FormItem>
                    <FormLabel>Category</FormLabel>
                    <FormControl><Input placeholder="general" {...field} data-testid="input-policy-category" /></FormControl>
                  </FormItem>
                )} />
                <Button type="submit" className="w-full" disabled={createMutation.isPending} data-testid="button-submit-policy">
                  {createMutation.isPending ? "Creating..." : "Create Rule"}
                </Button>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-20 w-full" />
          ))}
        </div>
      ) : policies && policies.length > 0 ? (
        <div className="space-y-3">
          {policies.map((policy) => (
            <Card key={policy.id} className="hover-elevate" data-testid={`card-policy-${policy.id}`}>
              <CardContent className="p-4">
                <div className="flex items-start gap-4">
                  <Switch
                    checked={policy.enabled}
                    onCheckedChange={(enabled) =>
                      toggleMutation.mutate({ id: policy.id, enabled })
                    }
                    data-testid={`switch-policy-${policy.id}`}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className={`text-sm font-semibold ${!policy.enabled ? "text-muted-foreground" : ""}`}>
                        {policy.name}
                      </span>
                      <SeverityBadge severity={policy.severity} />
                      <Badge
                        variant="outline"
                        className={`text-[10px] font-semibold uppercase tracking-wider no-default-hover-elevate no-default-active-elevate ${actionColors[policy.action] || ""}`}
                      >
                        {policy.action}
                      </Badge>
                      <Badge variant="secondary" className="text-[10px] no-default-hover-elevate no-default-active-elevate">
                        {policy.category}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mb-1.5">{policy.description}</p>
                    <code className="text-[11px] font-mono text-muted-foreground bg-muted/50 px-1.5 py-0.5 rounded">
                      {policy.pattern}
                    </code>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <ScrollText className="w-12 h-12 text-muted-foreground/30 mb-4" />
            <p className="text-sm text-muted-foreground">No policy rules defined</p>
            <p className="text-xs text-muted-foreground/60 mt-1">
              Create rules to control tool access and agent behavior
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
