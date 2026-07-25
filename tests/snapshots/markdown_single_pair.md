# Soroban Upgrade Safety Report

## Status: ❌ FAILED (Critical breaking changes detected)

### Summary Table

| Finding Severity | Count |
| :--- | :--- |
| **Critical** | 3 |
| **Warning** | 0 |
| **Info** | 1 |

**Recommended SemVer Bump**: `major`

**Baseline Source**: `Local File`

---

### Event Enum Case Added

- 🔵 Event enum 'StatusEvent': new case 'Archived' (value 4) added.

### Event Enum Case Value Changed

- 🔴 Event enum 'StatusEvent': case 'Paused' value changed from 2 to 3. This breaks data serialization.

### Function Signature Changed

- 🔴 Function 'initialize': parameter count changed from 1 to 2.

### Struct Field Removed

- 🔴 Struct 'ConfigData': field 'threshold' was removed. Backwards compatibility is broken.

### ⚠️ Action Required

- The new contract version modifies existing storage layouts or function interfaces.
- Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.

