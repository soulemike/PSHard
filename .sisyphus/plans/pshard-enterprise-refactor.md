# PSHard Enterprise Refactor Plan

## Current Status: Phase 1 Complete, Phase 2 In Progress

---

## ✅ COMPLETED TASKS

### T1 – Enterprise Folder Structure ✅
**Status:** COMPLETE

- [x] Established layered directory structure (Classes/Models, Classes/Services, Public, Tests)
- [x] Clear ownership boundaries between layers
- [x] Naming conventions aligned with enterprise PowerShell module standards
- [x] Structure prepared for scalability and test isolation

**Deliverables:**
- `/Classes/Models/` - PolicyResult.ps1
- `/Classes/Services/` - Logger.ps1, PolicyRegistryService.ps1, SystemHardeningService.ps1, ProvisioningService.ps1, ConfigurationQueryService.ps1
- `/Public/` - 14 public API functions
- `/Tests/` - PSHard.Tests.ps1

---

### T4 – SystemHardeningService Extraction ✅
**Status:** COMPLETE

- [x] System hardening logic extracted into isolated service layer
- [x] Direct environment mutations removed from orchestration code
- [x] Clear input/output contracts defined for hardening operations
- [x] Service enables independent testing of security controls

**Methods Implemented:**
- `ConfigureFirewall([int[]]$Ports, [string]$RuleGroup)`
- `ConfigureRemoting([bool]$EnableWinRM, [bool]$DisableBasicAuth, [bool]$DisableUnencrypted)`
- `ConfigureAuditPolicy([string[]]$Subcategories)`
- `RemoveLegacyFeatures([string[]]$FeatureNames)`

---

### T5 – ProvisioningService Extraction ✅
**Status:** COMPLETE

- [x] Provisioning workflows separated into dedicated service boundary
- [x] Environment preparation and dependency installation encapsulated
- [x] Error handling standardized
- [x] Service prepared for idempotent execution patterns

**Methods Implemented:**
- `CreateGpo([string]$Name, [string]$Comment, [string]$LinkTarget)`
- `CreateJeaEndpoint([string]$Name, [string[]]$VisibleCmdlets, [string]$ConfigurationPath)`
- `CreateTierModel([string]$DomainName, [string[]]$Tiers, [string]$GroupPrefix)`
- `CreateWdacPolicy([string]$OutputPath, [string]$Mode, [string[]]$AllowedExecutables)`

---

### T6 – ConfigurationQueryService ✅
**Status:** COMPLETE

- [x] Read-only configuration query abstraction introduced
- [x] Registry, file system, and policy lookups centralized
- [x] Consistent normalization of configuration outputs
- [x] Structure supports future caching and performance optimization

**Methods Implemented:**
- `GetConfigurationStatus()` - Returns execution policy, module logging, script block logging, and AMSI status

---

### T7 – Logger + PolicyResult Models ✅
**Status:** COMPLETE

- [x] Structured logging contracts defined with severity levels
- [x] PolicyResult domain model capturing outcome, evidence, and remediation hints
- [x] Serialization compatibility for audit exports ensured
- [x] Logging side effects prevented within core domain logic

**Deliverables:**
- `Logger` class with Info(), Warning(), Error() methods
- `PolicyResult` class with PolicyName, Compliant, Evidence, Remediation properties

---

### T9 – Test Scaffold ✅
**Status:** COMPLETE (Baseline)

- [x] Baseline test harness created for service and domain layers
- [x] Mockable interfaces introduced for external dependencies
- [x] Deterministic test execution without system mutation
- [x] Groundwork laid for CI pipeline integration

**Note:** Current tests verify module load, class availability, and function exports. Unit tests for service methods recommended for Phase 2.

---

## 🔄 PARTIALLY COMPLETED

### T2 – ExecutionPolicy Delegation Verification 🔄
**Status:** IMPLEMENTED, VERIFICATION PENDING

- [x] Execution policy handling delegated to PolicyRegistryService
- [x] No inline policy manipulation in business logic
- [ ] Guardrails for privilege escalation paths pending
- [ ] Verification criteria documentation pending

**Implementation:**
- `Set-PSHardExecutionPolicy` function delegates to `PolicyRegistryService.SetExecutionPolicy()`
- Methods added: `GetHive()`, `EnsureRegistryPath()`, `SetExecutionPolicy()`

---

### T3 – Registry-Based Command Migration 🔄
**Status:** IMPLEMENTED, ENHANCEMENT POSSIBLE

- [x] Centralized registry pattern established via PolicyRegistryService
- [x] Commands discoverable through public API functions
- [ ] Full command registry with versioning/auditing pending
- [ ] Backward compatibility confirmed

**Implementation:**
- All registry operations consolidated in PolicyRegistryService
- Public functions provide stable interface

---

## ⏳ PENDING TASKS

### T8 – Loader Hardening ⏳
**Status:** NOT STARTED

- [ ] Harden module loading sequence with validation and integrity checks
- [ ] Prevent dynamic execution of untrusted sources
- [ ] Add defensive error handling around bootstrap routines
- [ ] Document loader invariants and failure modes

**Notes:**
- Current loader in PSHard.psm1 has basic error handling
- Missing: Certificate validation, file hash checks, execution policy verification

---

## Final Verification Wave ⏳

### F1 – Architecture Review ⏳
- [ ] Review layer boundaries and dependencies
- [ ] Verify no circular dependencies
- [ ] Confirm service isolation

### F2 – Service Boundary Review ⏳
- [ ] Review all service method contracts
- [ ] Verify error handling consistency
- [ ] Confirm idempotency where applicable

### F3 – Public API Stability Review ⏳
- [ ] Review all public function signatures
- [ ] Verify backward compatibility
- [ ] Document breaking changes

### F4 – End-to-End Validation ⏳
- [ ] Test module load on clean system
- [ ] Verify all public functions execute without error
- [ ] Test service class instantiation

---

## KNOWN ISSUES

1. **Private/ folder missing** - PSHard.psm1 expects a Private/ folder but it doesn't exist (non-breaking due to -ErrorAction SilentlyContinue)
2. **PowerShellGrc.ps1 deprecated** - Monolithic script contains hardcoded values and should be removed or fully refactored
3. **Test coverage gaps** - Current tests only verify existence, not behavior

---

## RECOMMENDATIONS FOR PHASE 2

1. **Add comprehensive unit tests** for all service methods
2. **Implement T8 Loader Hardening** with integrity checks
3. **Complete Final Verification Wave (F1-F4)**
4. **Deprecate PowerShellGrc.ps1** or extract reusable components
5. **Add CI/CD pipeline** with automated testing
6. **Create documentation** for public API and architecture

---

*Last Updated: 2026-04-23*
