# Anti-VM and Anti-Debugging Checks – Master List (Al-Khaser + Advanced Hypervisor Techniques)

> **Scope note:** This file summarizes *detection concepts* for research use: how checks work and high‑level ways a **research VM / hypervisor** might be designed to behave more like real hardware. It is **not** meant as a recipe for evading real-world security or anti‑cheat systems.

---

## 1. Anti-Debugging Checks (Al-Khaser)

Each item: **What it is**, **How it works**, **High-level evasion idea for a research VM / app**.

### 1.1 `IsDebuggerPresent`

- **What:** Calls the Win32 API `IsDebuggerPresent`, which checks the `ProcessEnvironmentBlock->BeingDebugged` flag of the *current* process.
- **How:** If a user-mode debugger is attached through standard Windows debugging APIs, this flag is set, so `IsDebuggerPresent()` returns nonzero.
- **Evasion idea:**  
  - **For a VM/hypervisor:** This is a *guest OS API* check, not a VM check. It will only see debuggers *inside* the guest. When doing introspection from the host, do not attach a standard debugger in the guest; use out-of-band inspection.  
  - **For test tools:** If you *do* use a debugger in-guest, you can patch the PEB flag or hook `IsDebuggerPresent` for experimentation, but that is application-level, not VM-level behavior.

---

### 1.2 `CheckRemoteDebuggerPresent`

- **What:** Win32 API that checks whether a debugger is attached to a *target* process (not necessarily the caller).
- **How:** Internally uses `NtQueryInformationProcess` with debug info classes or examines PEB flags of the target process.
- **Evasion idea:**  
  - Use out-of-guest introspection instead of attaching debuggers to target processes. Guest processes are never “remotely debugged” in the usual sense.

---

### 1.3 PEB `BeingDebugged` flag

- **What:** The Process Environment Block (`PEB`) contains a `BeingDebugged` byte set by the OS when a debugger attaches.
- **How:** Malware / packers read `fs:[30h]` (x86) / `gs:[60h]` (x64) to get the PEB and inspect this flag directly instead of using APIs.
- **Evasion idea:**  
  - From the VM side, same as above: avoid in-guest debuggers.  
  - When experimenting with this flag, ensure your introspection/debugging is done externally (hypervisor or memory-snooping) so the OS never sets `BeingDebugged`.

---

### 1.4 PEB `NtGlobalFlag`

- **What:** `PEB->NtGlobalFlag` reflects process creation flags used by the debugger (e.g., heap checking, special pool).
- **How:** Values like `0x70` are associated with “debuggable” heaps when launched under a debugger.
- **Evasion idea:**  
  - Avoid launching processes under a debugger; launch normally in the guest and use introspection to track them.  
  - For research, you can emulate normal process-creation flags when debugging to see how samples behave.

---

### 1.5 Heap flags (`ProcessHeap->Flags` / `ForceFlags`)

- **What:** The process default heap structure contains flags that indicate debugging features (e.g., full-page heap).
- **How:** Under a debugger or Application Verifier, heap flags differ from “normal” ones. Malware checks them to detect instrumentation.
- **Evasion idea:**  
  - Do not enable special debug heaps in the guest for target processes.  
  - Use the hypervisor to log memory events rather than turning on page heap.

---

### 1.6 Low Fragmentation Heap (LFH)

- **What:** Checks whether the default heap is using LFH or certain debug configurations.
- **How:** Malware reads heap configuration and infers whether allocation behavior looks like a typical user environment versus an analysis setup.
- **Evasion idea:**  
  - Don’t alter heap behavior of the target process from user-mode tools. Keep OS defaults; put your instrumentation outside (hypervisor / VM).

---

### 1.7 `NtQueryInformationProcess` – `ProcessDebugPort`

- **What:** Native API that returns a debug port handle if a debugger is attached.
- **How:** `ProcessDebugPort != 0` → process is being debugged.
- **Evasion idea:**  
  - Same philosophy: no classic debugger attachments; introspect from outside so this returns 0 as on a normal system.

---

### 1.8 `NtQueryInformationProcess` – `ProcessDebugFlags`

- **What:** Another process information class; when queried with `ProcessDebugFlags`, a value of `0` means the process is debugged (flag cleared).
- **How:** Malware calls this and checks if flags are in the expected state for non-debugged processes.
- **Evasion idea:**  
  - Avoid debugger attachments; debug at the hypervisor layer. This check is then irrelevant.

---

### 1.9 `NtQueryInformationProcess` – `ProcessDebugObjectHandle`

- **What:** Returns a handle to the debug object associated with the process, if any.
- **How:** Malware expects `NULL` on normal execution; non-NULL implies debugger presence.
- **Evasion idea:**  
  - Again, avoid user-mode debugging. Hypervisor-based introspection doesn’t create a debug object.

---

### 1.10 `WudfIsAnyDebuggerPresent`, `WudfIsKernelDebuggerPresent`, `WudfIsUserDebuggerPresent`

- **What:** Functions used in Windows User-Mode Driver Framework / system components to detect debuggers, including kernel debuggers.
- **How:** They consult OS global debugger state.
- **Evasion idea:**  
  - Do not run the host with a kernel debugger attached when you want “clean” conditions.  
  - For CTF VMs, boot without KD; use logging/introspection in the hypervisor instead.

---

### 1.11 `NtSetInformationThread` – `HideThreadFromDebugger`

- **What:** Tells the kernel to hide a thread from user-mode debuggers.
- **How:** If a debugger is attached, this can detach a thread or cause misbehavior in debugger workflows.
- **Evasion idea:**  
  - For analysis, be aware that a sample may use this to prevent debugger visibility; your hypervisor–level introspection should still see the thread because it looks below the OS’s debug APIs.

---

### 1.12 `NtQueryObject` – `ObjectTypeInformation` / `ObjectAllTypesInformation`

- **What:** Enumerate kernel objects and inspect their types, including debug objects, named pipes, synchronization objects used by tools.
- **How:** Malware looks for objects corresponding to debuggers or sandboxes.
- **Evasion idea:**  
  - Don’t inject user-mode hooks or create named objects in the target process. Keep monitoring outside the guest or in a separate process with minimal interaction.

---

### 1.13 `NtClose` (invalid handle trick)

- **What:** Closing an invalid handle can behave differently under some debuggers (e.g., triggering exceptions or special handling).
- **How:** Malware passes an invalid handle to `NtClose` and watches for status codes or exceptions.
- **Evasion idea:**  
  - Know that debuggers may intercept such faults. Hypervisor-based observation doesn’t affect this behavior; the guest kernel remains in control.

---

### 1.14 `SetHandleInformation` – Protected Handles

- **What:** Sets handle flags like `HANDLE_FLAG_PROTECT_FROM_CLOSE`.
- **How:** Malware can use protected handles and watch for tampering by tools that inspect or close handles for instrumentation.
- **Evasion idea:**  
  - Avoid tools in the guest that enumerate/close handles of the target. Use external introspection for handle state inspection if needed.

---

### 1.15 `UnhandledExceptionFilter`

- **What:** Installs a custom top-level exception filter to observe/alter how exceptions are handled.
- **How:** Malware triggers deliberate exceptions and checks whether a debugger intercepts them or whether the custom filter runs.
- **Evasion idea:**  
  - Don’t rely on user-mode breakpoints that depend on exception chains the malware might replace. Use hardware breakpoints or hypervisor-controlled page faults instead.

---

### 1.16 `OutputDebugString` + `GetLastError`

- **What:** Sends a debug string; under some circumstances, `GetLastError` can reveal debugger presence (e.g., some debuggers change behavior).
- **How:** Malware calls `OutputDebugString` and inspects side effects.
- **Evasion idea:**  
  - Hypervisor introspection doesn’t use the Windows debug API, so this check won’t see it. Avoid in-guest debuggers that alter `OutputDebugString` behavior.

---

### 1.17 Hardware breakpoints (SEH / `GetThreadContext`)

- **What:** Checks for DRx (debug registers) being used or for structured-exception-handler patterns caused by single-step/hardware breakpoints.
- **How:** Malware calls `GetThreadContext`, inspects `Dr0–Dr3`, or uses SEH to detect single-step exceptions.
- **Evasion idea:**  
  - Prefer EPT-based execute/watchpoints at the hypervisor level; they don’t use DR registers visible to the guest.

---

### 1.18 Software breakpoints (`INT3` / `0xCC`)

- **What:** Detects patched instructions (0xCC) or monitors how `INT3` exceptions are handled.
- **How:** Malware scans its own code sections for unexpected 0xCC bytes, or triggers an `INT3` and watches who handles it.
- **Evasion idea:**  
  - Avoid patching code inside the guest binary. Use page-permission tricks (EPT execute-permission hooks) instead of inline breakpoints.

---

### 1.19 Memory breakpoints (`PAGE_GUARD`)

- **What:** Uses `VirtualProtect` with `PAGE_GUARD` or inspects pages to see if a debugger uses guard pages to trap accesses.
- **How:** Malware may check for unexpected guard pages or deliberately access a guard page and examine exception behavior.
- **Evasion idea:**  
  - Don’t rely on guard-page-based breakpoints in the guest. Use EPT/NPT or snapshots to monitor memory reads/writes.

---

### 1.20 Interrupt 0x2D / `INT 1`

- **What:** Legacy interrupt-based anti-debug tricks, using uncommon interrupts that behave differently when a debugger is attached.
- **How:** Malware issues these interrupts and checks if a debugger intercepts or alters normal exception flow.
- **Evasion idea:**  
  - Again, avoid classic debug APIs; hypervisor-level analysis should not interfere with interrupt handling.

---

### 1.21 Trap Flag (single-step)

- **What:** Uses the x86 Trap Flag (`TF`) in `EFLAGS` to cause single-step exceptions (#DB) and watch where/when they fire.
- **How:** Malware sets `TF`, executes an instruction that normally causes/avoids a VM-exit, and inspects the resulting context.
- **Evasion idea:**  
  - If you are writing a hypervisor, handle #DB consistently with real hardware (especially around VM-exiting instructions), as described in hypervisor detection research.  
  - For pure CTF work using standard VMs, note that this may reveal virtualization quirks you can’t easily change.

---

### 1.22 Parent process (Explorer.exe)

- **What:** Checks parent process; real user-launched programs typically have `explorer.exe` as parent, not analysis tools.
- **How:** Malware looks at the process tree via `CreateToolhelp32Snapshot` or `NtQueryInformationProcess`.
- **Evasion idea:**  
  - Launch the sample under realistic conditions (e.g., user double-click in guest), not directly from analysis tools. This is a workflow/automation concern rather than VM-specific.

---

### 1.23 `SeDebugPrivilege` / `csrss.exe` access

- **What:** Ensures the current process can access system processes or inspects if an unusual process has `SeDebugPrivilege`.
- **How:** Malware checks token privileges and tries opening handles to protected processes like `csrss.exe`.
- **Evasion idea:**  
  - Don’t grant excessive debug privileges to in-guest tools unless needed. Keep your analysis privileges on the host/hypervisor side.

---

### 1.24 `NtYieldExecution` / `SwitchToThread`

- **What:** Uses these to yield execution and see how the scheduler behaves; sometimes used as minor timing/behavior checks under debug.
- **How:** Malware can measure response or check for weird scheduling under heavy instrumentation.
- **Evasion idea:**  
  - Avoid extremely heavy single-threaded instrumentation inside the guest; hypervisor-based instrumentation spreads overhead differently and is harder to spot with such simple checks.

---

### 1.25 TLS callbacks

- **What:** Thread Local Storage callbacks run *before* the main entry point and can contain anti-debugging checks early on.
- **How:** Malware puts checks in TLS callbacks to preempt debuggers that break at `main` or `WinMain`.
- **Evasion idea:**  
  - Always run binaries from process creation, not by attaching later. Hypervisor-level tracing from process start will observe TLS behavior reliably.

---

### 1.26 Process jobs

- **What:** Uses Job objects to constrain processes or detect if the process is part of a job typically used by sandboxes/monitoring tools.
- **How:** Malware calls `IsProcessInJob` / job APIs to see if it’s sandboxed.
- **Evasion idea:**  
  - Avoid placing the sample into special jobs inside the guest for analysis unless you *want* to test job-based behavior.

---

### 1.27 Memory write watching / page exception breakpoints

- **What:** Samples set page protections to trap modifications and watch for other tools writing into their memory.
- **How:** Use `VirtualProtect`, `PAGE_GUARD`, or SEH handlers to see unexpected writes.
- **Evasion idea:**  
  - Don’t patch malware memory directly from in-guest tools. Treat the process as read-only and use the hypervisor to monitor/clone state externally.

---

### 1.28 API hook detection (module-bounds based)

- **What:** Detects if imported functions (e.g., in `kernel32.dll`) point outside their containing module, indicating hooks by monitoring tools.
- **How:** Malware walks IAT/EAT and checks if function pointers are within the expected module address range.
- **Evasion idea:**  
  - Avoid in-guest API hooking for analysis. Use hardware/VM-based instrumentation instead of patching system DLLs.

---

## 2. Anti-Injection Checks (Al-Khaser)

### 2.1 Enumerating modules (`EnumProcessModulesEx`, Toolhelp32, `LdrEnumerateLoadedModules`, direct PEB walk)

- **What:** Multiple redundant ways to enumerate loaded modules in a process.
- **How:** Malware cross-checks module lists via Win32 APIs, ToolHelp snapshot, native loader lists (PEB.Ldr), and direct memory structures to find:
  - Hidden injected modules,
  - Inconsistencies created by manual mapping.
- **Evasion idea:**  
  - Prefer *no* injected modules in the target process (keep analysis outside).  
  - If you do manual-mapping experiments, ensure all standard lists and memory views remain consistent.

---

### 2.2 Walking memory for hidden modules (`GetModuleInformation`, scanning PE headers)

- **What:** Scans address space for PE headers that are not listed in official module lists.
- **How:** Malware walks all committed regions and checks for valid PE signatures.
- **Evasion idea:**  
  - Avoid manual mapping of analysis DLLs into the target process.  
  - Keep injected code in separate processes and communicate via IPC if you must.

---

## 3. Anti-Dumping Checks (Al-Khaser)

### 3.1 Erasing PE header in memory

- **What:** Overwrites the in-memory PE header of the main image to break naive dump tools.
- **How:** Memory dumpers that reconstruct images from in-memory PE headers fail or produce corrupted dumps.
- **Evasion idea:**  
  - For analysis, use hypervisor-based dumps of raw memory plus manual reconstruction (using on-disk PE or recovered metadata), not tools that rely solely on in-memory headers.

---

### 3.2 Tampering with `SizeOfImage`

- **What:** Modifies the `SizeOfImage` field to mislead dumpers.
- **How:** Dump tools that trust `SizeOfImage` may cut off sections or map wrong ranges.
- **Evasion idea:**  
  - Again, capture raw memory regions using introspection and reconstruct the image using PE parsing logic independent of the in-memory header fields.

---

## 4. Timing / Anti-Sandbox Checks (Al-Khaser + Anti-Cheat Blog)

These are typical in sandboxes and also appear in advanced anti-cheat code.

### 4.1 `RDTSC` with `CPUID` (forced VM-exit timing)

- **What:** Measures execution time of sequences that trigger VM-exits.
- **How:** Pattern: `T0 = RDTSC; CPUID; T1 = RDTSC; delta = T1-T0`. In a VM, VM-exit/entry makes the delta much larger and more variable.
- **Evasion idea (high-level):**  
  - For a research hypervisor, implement a *virtual TSC* that adjusts time seen by the guest around VM-exits (e.g., subtract expected exit cost).  
  - Perfect mimicry is extremely hard; the goal is to avoid absurd outliers.

---

### 4.2 RDTSC “Locky version” with heap calls

- **What:** Same idea as 4.1 but mixes in innocuous API calls (`GetProcessHeap`, `CloseHandle`) to disguise timing tests.
- **How:** Measures total time and checks for virtualization-induced slowdown.
- **Evasion idea:**  
  - If you implement TSC virtualization, apply it generically so sequences with syscalls/APIs don’t stand out.  
  - For CTFs, this is mainly a reminder not to rely on naive timing manipulations in the guest.

---

### 4.3 Sleep-based timing checks (`Sleep`, `SleepEx`, `NtDelayExecution`)

- **What:** Detects “accelerated time” used by sandboxes to fast-forward malware.
- **How:** Call `Sleep(N)` or `NtDelayExecution`, then compare elapsed time using `GetTickCount`, `QueryPerformanceCounter`, or `RDTSC`. Large discrepancies imply time warping.
- **Evasion idea:**  
  - Don’t fast-forward time in your RE VM if you want to pass such checks.  
  - Run samples at real time; do out-of-band logging instead of time-scaling.

---

### 4.4 Looping short sleeps / checking time acceleration

- **What:** Uses many small sleeps in a loop to detect when sandboxes skip intervals.
- **How:** Compares expected duration with actual; big acceleration → sandbox.
- **Evasion idea:**  
  - Same as above: no aggressive time skipping if your goal is “realistic” behavior.

---

### 4.5 Timer APIs (`SetTimer`, `timeSetEvent`, wait APIs)

- **What:** Uses various timer mechanisms (standard, multimedia, waitable timer, timer queue) and waits (`WaitForSingleObject`, etc.) to detect abnormal timing.
- **How:** Some sandboxes only patch `Sleep`, not other timing functions.
- **Evasion idea:**  
  - If you manipulate time in a custom hypervisor, keep all relevant timing sources consistent, or simply don’t manipulate time for these tests.

---

### 4.6 ICMP timing (`IcmpSendEcho` – CCleaner malware style)

- **What:** Measures round-trip times of ICMP pings to detect network throttling or sleeps being skipped.
- **How:** Sandbox environments may fake or compress delays in network routines.
- **Evasion idea:**  
  - Don’t fake network latency for CTF labs if you want to pass such tests. Use real timing.

---

### 4.7 Big crypto loops

- **What:** Performs long CPU-bound operations and measures how long they take.
- **How:** Sandboxes that artificially speed up execution or only emulate parts of the code can show anomalies.
- **Evasion idea:**  
  - Avoid “fast-forward” execution modes that distort CPU-bound timing if you care about realistic behavior.

---

### 4.8 Advanced timing checks from anti-cheat research

Beyond Al-Khaser, anti-cheat research adds:

#### 4.8.1 INVD / WBINVD cache behavior

- **What:** Use cache-flush instructions (`INVD`/`WBINVD`) to measure differences in memory access times and infer virtualization.
- **Evasion idea:**  
  - Very difficult to fully emulate; for a research hypervisor, the best you can do is approximate expected latencies and avoid obviously incorrect behavior.

#### 4.8.2 APERF/MPERF Instruction Execution Time (IET)

- **What:** Uses performance counters (e.g., `APERF`) to measure per‑instruction execution time, especially across VM-exiting instructions.
- **Evasion idea:**  
  - Correctly virtualize performance counters or mask them as unsupported on CPU models where you can’t emulate them well.

#### 4.8.3 Multi-core timing & barriers

- **What:** Uses multiple threads across cores to measure cross-core timing and detect VM scheduling irregularities.
- **Evasion idea:**  
  - For educational hypervisors, coordinate TSC across vCPUs and avoid huge skew between cores.

---

## 5. Human Interaction / Generic Anti-Sandbox Checks (Al-Khaser)

### 5.1 Mouse movement and clicks

- **What:** Checks for realistic user input (mouse movement, click frequency).
- **How:** Samples API calls like `GetCursorPos`, `GetLastInputInfo`, monitoring if the cursor moves in human-like patterns.
- **Evasion idea:**  
  - For a realistic CTF VM, either drive input with a human or simulate plausible mouse events when testing these checks.

---

### 5.2 Suspicious filenames (`sample.exe`, `sandbox.exe`)

- **What:** Checks its own filename or path for known sandbox/analysis names.
- **How:** Using `GetModuleFileName` etc.
- **Evasion idea:**  
  - Give realistic names/paths to the sample in your analysis environment (“app.exe”, etc.).

---

### 5.3 System resource checks (RAM, disk size, CPU count)

- **What:** Uses `GlobalMemoryStatusEx`, `GetDiskFreeSpaceEx`, WMI, etc., to check total RAM, disk size, and CPU count.
- **How:** Sandboxes often allocate small RAM/disk and few CPUs; malware uses thresholds to decide if environment is “too small” to be real.
- **Evasion idea:**  
  - Configure your VM with realistic resources (e.g., 8+ GB RAM, 4+ cores, large virtual disk).

---

### 5.4 Genuine Windows, hostnames, usernames

- **What:** Checks activation, hostnames (like `SANDBOX`, `MALWARE-VM`), and usernames typical for lab images.
- **How:** Simple calls or registry queries.
- **Evasion idea:**  
  - Use realistic machine/username combinations and genuine Windows activation status in your VM.

---

## 6. Anti-Virtualization / Full-System Emulation Checks (Al-Khaser + Hypervisor Blogs)

Here we group checks from the Al-Khaser **Anti-Virtualization** section plus additional architectural checks from the hypervisor detection article.

### 6.1 Registry key value artifacts (BIOS / disk strings)

- **What:** Looks for specific vendor strings in registry keys describing SCSI devices, BIOS versions, and video BIOS (e.g., “VBOX”, “QEMU”, “VMware”).
- **How:** Reads keys like:
  - `HARDWARE\\DEVICEMAP\\Scsi\\...\\Identifier`
  - `HARDWARE\\Description\\System\\SystemBiosVersion`
  - `HARDWARE\\Description\\System\\VideoBiosVersion`
  - `SYSTEM\\ControlSet001\\Control\\SystemInformation` manufacturer/product
- **Evasion idea:**  
  - Configure your VM/firmware to use realistic OEM strings, not “VBOX”, “VMware”, or “QEMU”.  
  - For a custom VMM, synthesize SMBIOS/DMI data that mimics a typical physical machine model.

---

### 6.2 Registry key artifacts for VM tools/drivers

- **What:** Looks for presence of known VM guest additions / integration services.
- **How:** Scans registry paths such as:
  - `SOFTWARE\\Oracle\\VirtualBox Guest Additions`
  - `SYSTEM\\ControlSet001\\Services\\VBox*`  
  - `SOFTWARE\\VMware, Inc.\\VMware Tools`  
  - `SOFTWARE\\Wine`  
  - Hyper-V guest parameters, and generic disk/IDE/SCSI enumeration keys.
- **Evasion idea:**  
  - Don’t install vendor guest tools in VMs where you want to test detection.  
  - For a custom hypervisor, avoid creating those service keys at all.

---

### 6.3 File system artifacts (VM drivers and DLLs)

- **What:** Checks for specific files related to VirtualBox/VMware drivers, DLLs, and services.
- **How:** Tests for paths like:
  - `system32\\drivers\\VBox*.sys`, `vbox*.dll`, `vboxservice.exe`, `vboxtray.exe`
  - `system32\\drivers\\vm*.sys`, VMware tools executables.
- **Evasion idea:**  
  - Use a minimal Windows install without VirtualBox/VMware tools; for your own hypervisor, avoid installing such device drivers in the guest.

---

### 6.4 Directories for VM software

- **What:** Tests for installation directories:
  - `%PROGRAMFILES%\\Oracle\\VirtualBox Guest Additions\\`
  - `%PROGRAMFILES%\\VMWare\\`
- **How:** Typical user-land checks.
- **Evasion idea:**  
  - Don’t install these tools in your “stealth test” VM.

---

### 6.5 Descriptor table and TSS location (IDT, LDT, GDT, STR trick)

- **What:** Uses `SIDT`, `SLDT`, `SGDT`, and `STR` instructions to get descriptor table and Task State Segment addresses.
- **How:** On real hardware, these often reside in specific address ranges; hypervisors sometimes place them in easily-recognizable ranges or patterns.
- **Evasion idea:**  
  - For a custom hypervisor, place descriptor tables in plausible ranges and ensure values look like those on physical Windows machines.  
  - For stock VMs, you usually can’t change this; it’s a fundamental hypervisor design choice.

---

### 6.6 MAC address OUI checks

- **What:** Checks the Organizationally Unique Identifier (first bytes of MAC) against known VM vendors:
  - `08:00:27` (VirtualBox), `00:05:69`, `00:0C:29`, `00:1C:14`, `00:50:56` (VMware), etc.
- **How:** Enumerates network adapters and checks MAC prefixes.
- **Evasion idea:**  
  - Configure your VM’s NIC MAC address to a realistic non-VM OUI (or random OUI that isn’t known to belong to virtualization vendors) when testing.

---

### 6.7 Virtual devices (`\\\\.\\VBox*`, `\\\\.\\HGFS`, `\\\\.\\vmci`)

- **What:** Opens named device objects for VM-specific features:
  - `\\\\.\\VBoxGuest`, `\\\\.\\VBoxMiniRdrDN`, `\\\\.\\HGFS` (VMware shared folders), `\\\\.\\vmci`, etc.
- **How:** If these devices exist and respond, the environment is almost certainly virtualized.
- **Evasion idea:**  
  - Don’t expose vendor-specific devices in your guest; if building your own VMM, keep custom device interfaces private or disguised as generic hardware if you really need them.

---

### 6.8 Hardware device info via SetupAPI

- **What:** Uses `SetupDiEnumDeviceInfo` with `GUID_DEVCLASS_DISKDRIVE` and others to retrieve device descriptions for disk/virtual drives.
- **How:** Looks for names like “QEMU”, “VMWare”, “VIRTUAL HD”, “VBOX” in device descriptions.
- **Evasion idea:**  
  - Give virtual disk devices realistic manufacturer/model strings.  
  - In QEMU-based VMs, configure disk IDs to mimic common physical drives.

---

### 6.9 Firmware/SMBIOS/ACPI tables

- **What:** Reads SMBIOS and ACPI tables via Windows APIs or firmware functions looking for:
  - VirtualBox / VMware / QEMU SMBIOS vendor names.  
  - WAET table, specific ACPI devices, or a suspiciously low number of tables.
- **How:** These tables often explicitly reveal virtualization vendors.
- **Evasion idea:**  
  - For a custom hypervisor, synthesize SMBIOS and ACPI tables that match a specific real machine type, and avoid virtualization-specific extras.  
  - This is non-trivial but important for advanced stealth.

---

### 6.10 Driver services and processes

- **What:** Checks Windows services/drivers and running processes associated with VMs:
  - VirtualBox/VMware services (`VBoxService`, `vmtoolsd`, `vmwaretray`, etc.).
  - QEMU guest-agent (`qemu-ga.exe`) and generic tools like `looking-glass-host.exe`.
- **How:** Uses service APIs, process enumeration, and file checks.
- **Evasion idea:**  
  - Don’t run such services in a “stealth” analysis VM; keep it as bare and generic as possible.

---

### 6.11 Network shares and adapter names

- **What:** Looks for VM-specific network shares (VirtualBox shared folders) or adapter names (e.g., “VMware Network Adapter”).
- **How:** Uses Net APIs and WMI queries.
- **Evasion idea:**  
  - Avoid configuring shared folders and use generic adapter names.

---

### 6.12 WMI-based virtualization checks

- **What:** Uses WMI queries like:
  - `Win32_Bios` (SerialNumber)  
  - `Win32_PnPEntity` (DeviceId)  
  - `Win32_NetworkAdapterConfiguration` (MACAddress)  
  - `Win32_LogicalDisk` (Size)  
  - `Win32_ComputerSystem` (Model/Manufacturer)  
  - `MSAcpi_ThermalZoneTemperature`, `Win32_Fan` (thermal/fan info)
- **How:** Combines system model, BIOS strings, MAC OUIs, and resource sizes to infer virtualization.
- **Evasion idea:**  
  - Present realistic hardware info across all these classes when building your VMM profile; don’t just patch one field—keep the model coherent.

---

### 6.13 DLL exports and loaded DLLs (sandbox/AV hooks)

- **What:** Checks loaded modules for known security/sandbox DLLs:
  - `avghookx.dll`, `snxhk.dll`, `sbiedll.dll`, `dbghelp.dll` (in suspicious contexts), etc.
- **How:** Enumerates process modules and compares names/exports.
- **Evasion idea:**  
  - Avoid injecting security/sandbox DLLs into the target process when you want clean behavior; run monitoring components elsewhere.

---

### 6.14 CPU hypervisor bit and vendor CPUID leaves

- **What:** Uses `CPUID`:
  - With `EAX=1`, tests the hypervisor-present bit in `ECX`.  
  - With `EAX=0x40000000`, reads hypervisor vendor string:
    - `"KVMKVMKVM\0\0\0"`, `"Microsoft Hv"`, `"VMwareVMware"`, `"XenVMMXenVMM"`, `"prl hyperv  "`, `"VBoxVBoxVBox"`, etc.
- **How:** If hypervisor bit is set and vendor is in the known list, environment is virtualized.
- **Evasion idea:**  
  - For a “looks like bare metal” profile, clear the hypervisor bit and do not expose hypervisor-specific CPUID leaves.  
  - For a “Hyper-V client” profile, ensure CPUID values match exactly what real Hyper-V would report.

---

### 6.15 `NtQueryLicenseValue` – `Kernel-VMDetection-Private`

- **What:** Reads a hidden license value used by Windows to record virtualization-related state.
- **How:** Anti-cheat/malware can call `NtQueryLicenseValue` with this key and interpret the result.
- **Evasion idea:**  
  - Difficult to change from userland; if you build a hypervisor that integrates with Windows licensing mechanisms, you’d ensure such internal values match expected bare-metal behavior. For normal CTF VMs, you typically accept that this reveals virtualization.

---

### 6.16 Advanced architectural hypervisor checks (from anti-cheat article)

Beyond Al-Khaser, the hypervisor detection article describes:

#### 6.16.1 Unimplemented MSR behavior (“garbage write” detection)

- **What:** Writes to reserved/unimplemented MSRs and sees whether they cause `#GP` or appear to succeed.
- **Evasion idea:**  
  - Implement MSR virtualization to match real hardware’s behavior exactly for these ranges.

#### 6.16.2 Debug exception (#DB) with Trap Flag and VM-exiting instructions

- **What:** Sets TF, executes a VM-exiting instruction (e.g., `CPUID`), and checks if #DB is delivered at the expected RIP.
- **Evasion idea:**  
  - Carefully forward #DB/T_F behavior through VM-exit/entry paths in your hypervisor so it matches bare metal semantics.

#### 6.16.3 Last Branch Record (LBR) virtualization checks

- **What:** Enables LBR and inspects recorded branches around VM-exits for inconsistencies.
- **Evasion idea:**  
  - Either correctly virtualize LBR MSRs or present a CPU model where LBR is not supported.

#### 6.16.4 Synthetic MSRs (0x40000000+ range)

- **What:** Probes hypervisor-specific MSRs to see if they exist and how they behave.
- **Evasion idea:**  
  - If you claim no hypervisor, reserved MSR accesses should `#GP`. Don’t accidentally expose vendor-specific MSRs unless you match a real system that has them.

#### 6.16.5 CRn access exiting and CR4.VMXE mask

- **What:** Tests how CR access VM-exiting is configured and whether CR4.VMXE behaves as expected (e.g., VMX instructions must #UD when disabled).
- **Evasion idea:**  
  - Mirror real hardware: ensure CR4 bits and VMX instructions’ behavior align with the advertised CPU capabilities.

#### 6.16.6 CPUID leaf consistency

- **What:** Compares CPUID leaves across multiple calls, modes, or cores to find inconsistencies.
- **Evasion idea:**  
  - Provide a coherent CPUID model and keep it stable across cores and over time.

#### 6.16.7 WoW64 descriptor table mismatch

- **What:** Checks differences in descriptor tables (GDT/IDT) between 32‑bit WoW64 and 64‑bit modes; some hypervisors get this wrong.
- **Evasion idea:**  
  - Implement correct descriptor tables for each mode; don’t reuse 64‑bit values blindly for 32‑bit compat mode.

---

## 7. Analysis Tool Detection (Al-Khaser)

### 7.1 Common reverse-engineering tools as processes

- **What:** Scans running processes for debuggers and RE tools:
  - OllyDbg, Immunity, WinDbg, IDA, x64dbg, Cheat Engine, Process Explorer, Process Hacker, Frida, etc.
- **How:** Uses `CreateToolhelp32Snapshot` or WMI.
- **Evasion idea:**  
  - Run these tools **outside** the guest (on the host) and use VM introspection instead, or rename tools if you must run them in-guest (for CTF experiments).

---

### 7.2 Sandbox / monitoring frameworks

- **What:** Looks for JoeBox, Sandboxie, Comodo container DLLs, logging DLLs, etc.
- **How:** Module enumeration, DLL name checks.
- **Evasion idea:**  
  - Keep dedicated sandbox DLLs out of the target process when you want a clean “real user” environment; let the hypervisor observe from the outside.

---

## 8. Anti-Disassembly Tricks (Al-Khaser)

### 8.1 Jumps with constant condition / same target

- **What:** Constructs control-flow that confuses linear disassemblers:
  - e.g., conditional jumps that always go to the same place, opaque predicates.
- **How:** Static tools may misinterpret reachable/unreachable code.
- **Evasion idea (for analysts):**  
  - Use dynamic analysis and hypervisor-based tracing to recover real control-flow instead of relying only on static disassembly.

---

### 8.2 Impossible disassembly sequences

- **What:** Inserts bytes that parse differently depending on starting offset, causing misalignment and bogus instructions.
- **How:** Disassemblers may show nonsense code or miss real instructions.
- **Evasion idea:**  
  - Treat static view as advisory; rely on actual executed instructions via runtime tracing.

---

### 8.3 Function pointer / return pointer abuse

- **What:** Uses computed jumps/returns through manipulated pointers to hide real control-flow.
- **How:** Makes code paths hard to follow statically.
- **Evasion idea:**  
  - Use coverage-guided tracing in your introspection VM to log indirect branch targets and reconstruct the CFG dynamically.

---

## 9. Code / DLL Injection Techniques (Al-Khaser – for completeness)

> These are not “anti” checks but techniques Al-Khaser *uses* to inject code. The VM/introspection tool may want to detect or simulate them.

- **CreateRemoteThread**
- **SetWindowsHookEx**
- **NtCreateThreadEx**
- **RtlCreateUserThread**
- **APC injection (`QueueUserAPC`, `NtQueueApcThread`)**
- **RunPE (GetThreadContext / SetThreadContext process hollowing)**

Each of these:
- **What:** Creates a thread or modifies an existing one in a target process so that it starts executing attacker-controlled code.
- **How:** Uses standard or native APIs to manipulate thread contexts and module loading.
- **Evasion idea (defensive):**  
  - A research hypervisor can watch for cross-process handle usage, remote thread creation, and unusual context changes using EPT hooks and kernel-structure inspection.

---
