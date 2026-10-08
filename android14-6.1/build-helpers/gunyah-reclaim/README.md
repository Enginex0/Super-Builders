# E3Q reclaim contract v1

Applied after the immutable Gunyah/IRQFD/SCM/boot-context and adaptive-backing
helpers. This repairs ownership rollback; it does not by itself make Terminal
work, authenticate a guest, or prove the cause of the earlier external-abort panic.

- Keep the outgoing mapped SCM owner and restore that same owner, not hardcoded 3.
- Record the successfully assigned prefix and unwind in reverse. Stop on a failed
  reclaim; no later success can overwrite its error. An SCM failure is treated as
  potentially side-effecting: keep the whole mapping pinned even if the known
  prefix rolled back. No automatic retry of uncertain operations.
- Keep RM handle/state on MEM_APPEND errors. Reclaim is deferred to normal VM
  teardown, which resets first. A failed/invalid initial RPC response cannot prove
  RM non-acceptance: quarantine, without an unsafe SCM rollback under a possible RM owner.
- HOST_OWNED is separate from INVALID_HANDLE. Unpin only after both ownership layers
  are confirmed restored. Preserve mapping/VM/mm/RM/module references on failure,
  link the VM into a quarantine list, and block new Gunyah starts until reboot.
- Pin the platform module while it owns a parcel. Matching ops cookie is required
  before assignment; new module also requires the new kernel's initialized state.
  Old/new mixed pairs fail before SCM ownership changes. The stock Samsung named
  VM path `/dev/qgunyah` and qcom-scm provider are not modified.
- Public structs/signatures are unchanged. The existing Android backport reserve
  words carry the private contract. CONFIG_ANDROID_VENDOR_OEM_DATA=y is required;
  verify strict KMI, stock import CRCs and absence of new QCOM debug imports in CI.

The QCOM source identity/mapping is retained from the earlier outgoing path; this
is not a claim that the phone's actual host VMID was measured as different from 3.

`test-e3q-gunyah-reclaim.py` checks transformation/idempotence, unrelated safety
markers, and compiles the exact emitted C bodies against a fake RM/SCM/allocator.
Address/undefined behavior sanitizers and a C compiler are mandatory in CI. It
also runs against the final generated kernel sources before the expensive build.
These tests do not emulate QHEE or prove live VM stability.

Fixtures: AOSP common 4bd1b41bff8bb87bed8c3621fa2bb5b2e96f5d8c, relevant memory
transforms from Super-Builders 5395ac07928dc1852375cf1f63735328a4de41e8 and pinned
helpers def60b77, 882a22c8, f314a327. Fixture vm_mgr omits unrelated boot-context and
CMA additions; tests against the final build tree cover the real resulting source.
Original GPL headers are retained; fixture normalized-content SHA256s are pinned.

This is a diagnostic candidate, not permission to run another phone VM. Never
force-unload a module with quarantined parcels or relax the memory isolation to
work around a failed reclaim. Reboot is the only supported quarantine recovery,
and must be separately authorized by the device owner.
