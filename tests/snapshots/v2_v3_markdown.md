# Soroban Upgrade Safety Report

## Status: ❌ FAILED (Critical breaking changes detected)

### Summary Table

| Finding Severity | Count |
| :--- | :--- |
| **Critical** | 3 |
| **Warning** | 2 |
| **Info** | 0 |

**Recommended SemVer Bump**: `major`

---

### Event Enum Case Removed

- 🔴 Event enum 'StatusEvent': case 'Archived' (value: 4) was removed. On-chain data or events relying on this value will be invalid.

### Event Enum Case Value Changed

- 🔴 Event enum 'StatusEvent': case 'Paused' value changed from 3 to 2. This breaks data serialization.

### Function Signature Changed

- 🔴 Function 'initialize': parameter count changed from 2 to 1.

### Parameter Renamed

- 🟡 Function 'execute_action': parameter 0 renamed from '_config' to '_new_config'.

### Struct Field Added

- 🟡 Struct 'ConfigData': new field 'threshold' appended. Existing storage entries won't have this field — ensure migration handles defaults.

### ⚠️ Action Required

- The new contract version modifies existing storage layouts or function interfaces.
- Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.
