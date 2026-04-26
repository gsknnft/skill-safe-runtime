# @gsknnft/skill-safe-runtime

Runtime monitoring contracts for agent skill execution.

This package does not execute agents and does not provide a sandbox by itself.
It defines the shared decision model for tool allowlists, permission levels,
taint labels, and trace export so hosts such as WorkLab, Campus, Claw3D, or
agent-chat-core can enforce runtime policy consistently.

## Use

```ts
import { createRuntimeMonitor } from "@gsknnft/skill-safe-runtime";

const monitor = createRuntimeMonitor({
  allowlist: {
    default: ["read_file", "search"],
    byTrustLevel: {
      community: ["search"],
    },
  },
});

const decision = monitor.evaluateToolCall({
  toolName: "delete_file",
  trustLevel: "community",
  requestedPermission: "delete",
});
```

