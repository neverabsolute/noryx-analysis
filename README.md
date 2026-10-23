# Noryx "Anticheat" — decompiled source and analysis

This repository contains the decompiled C# source of **Noryx.exe**, a program
distributed to Rust players as a "PC checker" that supposedly helps server
communities catch cheaters. It is published here as a worked example of a tool
nobody should run on their machine, and as a reference for anyone asked to run
something like it.

Players reported receiving game bans after using it. The analysis below explains
what the program actually does. The short version: it is a read-only but
extremely invasive forensic collector, bundled with an administrator-level
remote-desktop feature, shipped unsigned by an anonymous operator, and it opens a
memory-read handle to the running Rust game process.

Nothing here is an accusation that the operators intend harm. The point is that
the design itself is unacceptable regardless of intent.

## Contents

| Path | What it is |
| --- | --- |
| `src/` | The main assembly `Noryx.dll`, decompiled to C# with ILSpy. 127 files, no obfuscation was present. |
| `tools/unbundle.py` | Script that carves the .NET single-file bundle, including when the bundle marker has been stripped (as it was here). |
| `README.md` | This analysis. |

The original binary and the third-party DLLs it bundles are deliberately not
included.

## Sample identification

| Field | Value |
| --- | --- |
| File name | `Noryx.exe` |
| Size | 166,797,586 bytes (159 MiB) |
| SHA-256 | `24951d3cc6348827ee6cfe644f2c3894a00bf6e883a9911ac64b5d7f5bf90325` |
| MD5 | `cb68448dc66bb2fb0938b44c306fcbed` |
| Type | PE32+ GUI, .NET 8 single-file bundle (`singlefilehost`), WinForms |
| Internal name / version | `Noryx.dll` 3.1.0.0 |
| Authenticode signature | None |
| Manifest | `requestedExecutionLevel level="requireAdministrator"` |
| PE timestamp | 2026-08-20 |
| Language | Portuguese UI, with Spanish and English localisation |
| Backend | `https://noryx-anticheat.shardweb.app` |

The .NET single-file bundle marker (the SHA-256 of `.net core bundle`) was
removed from the host executable, which breaks every off-the-shelf extractor.
The manifest itself was still intact at file offset `0x9f0b3e5`, so the
contents were recovered by locating the header by pattern. Once extracted,
`Noryx.dll` decompiled cleanly.

## How it works

### Session flow

1. The player types a 6-character code shown in-game. The app posts it to
   `api/noryx/client/claim` and receives a session token.
   (`AgentMainForm.ValidateCodeAsync`)
2. A consent screen asks the player to authorise "analysis of executables,
   processes and technical records". An optional second checkbox links a Discord
   account via OAuth. (`AgentMainForm.ShowConsent`)
3. The app fetches detection rules from `api/agent/<token>/rules`: filename,
   path, SHA-256, signer and PowerShell substring patterns, plus a "threat
   catalog" of cheat brand names, domains and Discord invites.
   (`Program.LoadRulesAsync`, `RulesResponse`, `DetectionRule`)
4. It relaunches itself as a hidden `--collection-worker` child, which in turn
   spawns `--file-worker` children to hash and inspect files in isolation.
   Fifty-four collectors run under a 15-minute budget. (`Program`,
   `CollectionProcessRunner`, `BoundedInspectionQueue`)
5. The result is serialised to JSON, capped at 6 MB, gzipped and posted to
   `api/agent/<token>/report`. A DPAPI-encrypted copy is kept for 24 hours in
   `%LOCALAPPDATA%\Noryx\Recovery` so the upload can be retried.
   (`TransportReport`, `ReportUploadRetry`, `AgentRecoveryStore`)
6. After consent, the UI polls `api/agent/<token>/remote/admins` every five
   seconds for a remote-support request. See below.

### Reading the Rust process

This is the behaviour that prompted the analysis.

`ProcessMemoryIntegrityCollector` opens every process named `rust`,
`rustclient`, `steam`, `steamwebhelper` or `explorer` with
`PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`, walks the whole address space
with `VirtualQueryEx`, and for each committed, private, executable region calls
`ReadProcessMemory` to read two bytes and check for an `MZ` header. Hits are
reported as `PotentialManualMap`. This is a well-known heuristic for detecting
manually mapped cheat modules.

`DeepForensicCollector.CollectRustModules` and
`ProcessModuleIntegrityCollector` enumerate every DLL loaded in `RustClient`
(and in `lsass`, `csrss`, `winlogon`, `services`, `svchost` and `dwm`) and
Authenticode-verify each one.

The program never writes to another process. There is no `WriteProcessMemory`,
`CreateRemoteThread`, `VirtualAllocEx`, `NtMapViewOfSection`,
`SetWindowsHookEx` or similar anywhere in the decompiled code or in the bundled
third-party libraries. It does not inject, hook or patch the game.

It also does not check whether the game is running before doing this. If a
player runs the scan with Rust open, an unsigned, elevated, third-party process
opens a read handle to the game and reads game memory. That is the same
handle pattern a kernel anti-cheat is designed to notice. Whether Easy
Anti-Cheat strips the handle, logs it, or treats it as a ban signal cannot be
determined from this binary, and the reports of bans could also reflect
selection bias: people are usually only told to run a "PC checker" when they
are already suspected.

### Remote desktop

`RemoteSupportClient` and `RemoteInput` implement a complete remote-control
client:

- The admin requests a session server-side. The player sees a Yes/No dialog
  saying the admin "requested to share the screen and control the mouse and
  keyboard".
- On Yes, the client streams JPEG screenshots of the selected monitor at roughly
  four frames per second over a WebSocket, with an HTTPS polling fallback.
- Incoming JSON events are turned into real mouse and keyboard input with
  `SendInput`. The mode is hard-coded to `"control"`; there is no view-only
  option.
- The client reports to the server whether it is elevated. Because of the
  manifest, it always is, so the remote operator drives an administrator
  session.
- Declining suppresses the prompt only until the admin withdraws and re-issues
  the request.

### What is collected and uploaded

Only metadata, hashes and match flags are uploaded, never file contents. The
scope is still far beyond anything needed to find a cheat:

- **Browser download history**, unfiltered: URLs, referrers, page URLs and
  on-disk paths for Chrome, Edge, Brave, Chromium, Vivaldi, Yandex, Opera,
  Opera GX and Firefox. (`BrowserDownloadsCollector`)
- **Browsing history**: the 25,000 most recent URLs per profile are read and
  the entries matching cheat-related terms are uploaded. Raw SQLite pages and
  WAL files are also carved to recover deleted history.
  (`BrowserHistoryCollector`, `BrowserArtifactRecoveryCollector`)
- **Every Steam account** ever logged in on the machine: SteamID64, account
  name, persona name, last login and the "remember password" flag.
  (`SteamAccountCollector`)
- **Hardware fingerprint** hashed from the motherboard UUID, baseboard serial,
  BIOS serial and CPU ID, plus machine name and OS version.
  (`WindowsEnvironmentCollector`)
- **A recursive listing of every file on every connected USB drive.**
  (`Program.CollectConnectedUsbFiles`)
- **A sweep of every fixed and removable drive** for `.exe .dll .sys .bat .cmd
  .ps1 .com .scr .zip .rar .7z`: path, size, SHA-256, signer, compile time, PE
  entropy, suspicious import names and archive entry names. `.lua` and `.ahk`
  files under 512 KB are read and regex-checked for recoil macros.
  (`Program.CollectCandidateFiles`, `PeInspectionCollector`,
  `RustInputScriptCollector`)
- **Raw USN journal reads** on every NTFS volume via `\\.\C:` covering 45 days
  of created, deleted and renamed files. (`UsnActivityCollector`,
  `UsnDeletionCollector`)
- **Windows forensic artifacts**: Security log process creation and termination
  events, system time changes, Defender detections and exclusions, PowerShell
  history and script-block events, Prefetch, Amcache, ShimCache, BAM,
  UserAssist, MUICache, PCA, Recycle Bin original paths, recent shortcuts,
  scheduled tasks, services, drivers with hashes, autoruns, Secure Boot and
  test-signing state, VM detection, USB device history, serial devices (with
  explicit checks for Arduino and MAKCU hardware), live TCP connections with
  owning process, DNS cache matched against the cheat domain list, and any
  window flagged to hide from screen capture.

### What it does not do

- No persistence: it writes no Run keys, services or scheduled tasks.
- No credential, cookie or password theft.
- No code execution driven by the server. The rules it downloads are match
  patterns only.
- No modification of the game or any other process.

## Why nobody should run this

1. **It demands administrator rights and is not code-signed.** There is no way
   to verify who built it or that the copy you have is the copy that was
   analysed. The bundle marker was deliberately removed to make inspection
   harder.
2. **It opens the game's memory from an untrusted process.** Even though it only
   reads, that is exactly what anti-cheat drivers are built to catch. Nobody
   should take that risk on their account to satisfy a community admin.
3. **It ships a full remote-control client.** Clicking Yes hands an anonymous
   operator an elevated session with mouse and keyboard. The consent dialog is
   the only safeguard, and it can be re-issued until the player gives in.
4. **The data collection is wildly disproportionate.** Every Steam account on
   the machine, every file on any USB stick, forty-five days of filesystem
   journal, a full download history and a hardware fingerprint go to a
   third-party server with no stated retention policy that can be checked.
   A clean result still means all of that was uploaded.
5. **The methodology does not even work well.** Keyword matching on browser
   history flags anyone who searched "rust cheat" to read about cheating.
   Serial-device matching flags every Arduino hobbyist. Unsigned DLLs under
   the user profile are "suspicious" by definition, which includes most
   developer tooling. False positives are treated as findings for a human
   admin to judge, with the player having no visibility into the report.
6. **Legitimate anti-cheat does not work this way.** Real anti-cheat is signed,
   runs with the game, is accountable to the game publisher, and does not
   stream your desktop to a Discord moderator.

If a community asks you to run a tool like this, the right answer is no.

## How the source was recovered

```sh
# 1. Carve the bundle (the marker was stripped, so the header is found by pattern)
python3 -I tools/unbundle.py Noryx.exe extracted/

# 2. Decompile with ILSpy (ilspycmd 9.1.x targets .NET 8; the latest requires a newer SDK)
dotnet tool install --tool-path ./dotnet-tools ilspycmd --version 9.1.0.7988
./dotnet-tools/ilspycmd -p -o src -r extracted extracted/Noryx.dll
```

The analysis was entirely static. The binary was never executed.

## Disclaimer

This repository is published for education and consumer protection. The
decompiled code is the work of its original authors and is reproduced here for
the purpose of analysis and commentary. Do not build, run or distribute it as
a working program.
