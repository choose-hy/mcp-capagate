# Capability Graph

The Capability Graph is the core representation used by MCP CapaGate.

Each `CapabilityNode` records:

- tool and server identity
- extracted capabilities
- risk level
- data sensitivity
- blast radius
- required controls
- evidence and confidence

Edges model how tools can combine:

- `can_read_then_send`
- `can_exfiltrate_to`
- `can_mutate_state`
- `can_execute_code`
- `can_access_private_data`
- `potential_shadowing`
- `potential_tool_chain`

The graph is hashable, which makes it useful for drift detection in CI.
