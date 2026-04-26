import type { SkillTrustLevel } from "@gsknnft/skill-safe";

export type PermissionLevel = "observe" | "read" | "write" | "network" | "execute" | "delete";
export type RuntimeDecisionAction = "allow" | "review" | "block";

export type ToolAllowlist = {
  default: string[];
  byTrustLevel?: Partial<Record<SkillTrustLevel, string[]>>;
  bySkillSource?: Record<string, string[]>;
};

export type TraceEvent = {
  timestamp: string;
  type: "tool-call" | "permission-escalation" | "taint-sink" | "decision";
  action: RuntimeDecisionAction;
  message: string;
  metadata?: Record<string, unknown>;
};

export type TraceExporter = {
  export(event: TraceEvent): void | Promise<void>;
};

export type RuntimeMonitorConfig = {
  allowlist: ToolAllowlist;
  permissionDecay?: boolean;
  traceExporter?: TraceExporter;
};

export type RuntimeToolCall = {
  toolName: string;
  trustLevel: SkillTrustLevel;
  skillSource?: string;
  requestedPermission?: PermissionLevel;
  tainted?: boolean;
  sink?: "filesystem" | "network" | "shell" | "credential" | "approval" | "memory";
  metadata?: Record<string, unknown>;
};

export type RuntimeDecision = {
  action: RuntimeDecisionAction;
  reason: string;
  requiredApproval: boolean;
  permissionLevel?: PermissionLevel;
};

export type RuntimeMonitor = {
  evaluateToolCall(call: RuntimeToolCall): RuntimeDecision;
};

const PERMISSION_RANK: Record<PermissionLevel, number> = {
  observe: 0,
  read: 1,
  write: 2,
  network: 3,
  execute: 4,
  delete: 5,
};

const DANGEROUS_SINKS = new Set<RuntimeToolCall["sink"]>([
  "network",
  "shell",
  "credential",
  "approval",
]);

const nowIso = (): string => new Date().toISOString();

const emit = (exporter: TraceExporter | undefined, event: Omit<TraceEvent, "timestamp">): void => {
  void exporter?.export({
    timestamp: nowIso(),
    ...event,
  });
};

const resolveAllowedTools = (
  allowlist: ToolAllowlist,
  trustLevel: SkillTrustLevel,
  skillSource?: string,
): Set<string> => {
  const tools = [
    ...allowlist.default,
    ...(allowlist.byTrustLevel?.[trustLevel] ?? []),
    ...(skillSource ? allowlist.bySkillSource?.[skillSource] ?? [] : []),
  ];
  return new Set(tools);
};

export const createRuntimeMonitor = ({
  allowlist,
  permissionDecay = true,
  traceExporter,
}: RuntimeMonitorConfig): RuntimeMonitor => ({
  evaluateToolCall(call) {
    const allowedTools = resolveAllowedTools(allowlist, call.trustLevel, call.skillSource);
    const permissionLevel = call.requestedPermission ?? "observe";

    if (!allowedTools.has(call.toolName)) {
      const decision: RuntimeDecision = {
        action: "block",
        reason: `Tool "${call.toolName}" is not allowed for ${call.trustLevel} skills.`,
        requiredApproval: true,
        permissionLevel,
      };
      emit(traceExporter, {
        type: "tool-call",
        action: decision.action,
        message: decision.reason,
        metadata: call.metadata,
      });
      return decision;
    }

    if (call.tainted && call.sink && DANGEROUS_SINKS.has(call.sink)) {
      const decision: RuntimeDecision = {
        action: "block",
        reason: `Tainted input reached dangerous ${call.sink} sink.`,
        requiredApproval: true,
        permissionLevel,
      };
      emit(traceExporter, {
        type: "taint-sink",
        action: decision.action,
        message: decision.reason,
        metadata: call.metadata,
      });
      return decision;
    }

    if (permissionDecay && PERMISSION_RANK[permissionLevel] >= PERMISSION_RANK.execute) {
      const decision: RuntimeDecision = {
        action: "review",
        reason: `High-risk permission "${permissionLevel}" requires explicit approval.`,
        requiredApproval: true,
        permissionLevel,
      };
      emit(traceExporter, {
        type: "permission-escalation",
        action: decision.action,
        message: decision.reason,
        metadata: call.metadata,
      });
      return decision;
    }

    const decision: RuntimeDecision = {
      action: "allow",
      reason: "Tool call is allowed by runtime policy.",
      requiredApproval: false,
      permissionLevel,
    };
    emit(traceExporter, {
      type: "decision",
      action: decision.action,
      message: decision.reason,
      metadata: call.metadata,
    });
    return decision;
  },
});
