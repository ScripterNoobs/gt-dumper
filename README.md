# gt-dumper — gtmapper

Growtopia (x64) offset mapper. Point it at a **dumped** `Growtopia.exe` and it regenerates
`offsets.h` and `offsets.cs` for that build: 109 named function RVAs plus every Lua / RmlUi
binding table, with nothing to maintain by hand between game updates.

**Contact:** Discord `.selahattingt`

## Why

Growtopia ships packed and the functions you care about move with every update. Byte
signatures break all the time, and there is usually no old binary to diff against.
gtmapper resolves each function from what stays stable across builds instead: the strings a
function references, who calls whom, and a handful of tiny accessor patterns. One run per
update, no manual work unless the game itself changes a string.

## Features

- Single C++17 source file, no dependencies, builds with MSVC in a second.
- 109 offsets: `SendPacket`, `SendPacketRaw`, `ProcessTankUpdatePacket`,
  `VariantList::SerializeFromMem`, `GetApp` / `GetClient` / `GetPacketProcessor` /
  `GetLocalAvatar`, packet / world / tile / inventory / dialog / UI / pet handlers and more.
- All `luaL_Reg`-style binding tables (Lua 5.4 standard libraries and the RmlUi Lua API) with
  the RVA of every bound C function.
- Derived struct offsets in the output comments (`App::client`, `App::packetProcessor`,
  `PacketProcessor::localAvatar`).
- Automatic drift check: when an `offsets.h` from the previous build is present, old and new
  addresses are compared and any order inversion is flagged.
- Refuses the packed executable with a clear message instead of producing garbage.

## Build

Requires Visual Studio 2019 or newer with the C++ workload.

```bat
build.bat
```

`build.bat` locates Visual Studio with `vswhere`, runs `vcvars64.bat` and compiles
`gtmapper.cpp` into `gtmapper.exe`. A prebuilt binary is attached to each
[release](../../releases).

## Usage

```bat
gtmapper.exe gt-dumped.exe
gtmapper.exe -i gt-dumped.exe
```

That is all. `offsets.h` and `offsets.cs` are written next to the input file. If an
`offsets.h` already exists there it is compared with the new result before being
overwritten, and a one-line summary is printed.

| option | meaning |
|---|---|
| `-o <dir>` | write the two files into `<dir>` instead of next to the exe |
| `--verify <offsets.h>` | compare against a specific older `offsets.h` |
| `-v` | verbose: every recipe with its candidates, all Lua tables, full drift table |

Exit codes: `0` everything resolved, `1` bad input (packed exe, unreadable file),
`3` at least one recipe unresolved (files are still written, the entry is `0` and marked
`!! NOT FOUND`).

## Input: the dump

The game's packer leaves `.text`, `.rdata` and `.data` empty in the file on disk and wipes
the `.pdata` section, so gtmapper needs a **memory dump with rebuilt sections** (Scylla,
pe-sieve, or any dumper that keeps the section table and the data directories). Function
boundaries are read from the exception data directory, which the packer moves into its own
section but leaves intact.

## Output

`offsets.h`

```cpp
// Growtopia x64 offsets - generated 2026-09-10 16:21:40Z
// image base 0x140000000  build hash 744532391c2bd306  (PE timestamp 2026-09-09 11:59:05Z)
#pragma once
#include <cstdint>
namespace gt {
    constexpr uintptr_t kSendPacket = 0x00C464C0; // SendPacket(int type, std::string* text, ENetPeer* peer)
    constexpr uintptr_t kSendPacketRaw = 0x00C465E0; // SendPacketRaw(int type, void* data, int len, ENetPeer* peer, int flags)
    ...
    constexpr uintptr_t kGetClient = 0x00A16270; // kAppClientOffset = 0xB10 (derived)

    struct Binding { const char* name; unsigned int rva; };
    struct BindingTable { unsigned int rva; const Binding* rows; int count; };
    constexpr Binding kBind0[] = { {"_G", 0x015E6E40}, {"package", 0x015F2200}, ... };
    constexpr BindingTable kBindingTables[] = { {0x01FACAB0, kBind0, 10}, ... };
}
```

`offsets.cs`

```cs
public static class Offsets {
    public const Int64 SendPacket = 0xC464C0; // SendPacket(int type, std::string* text, ENetPeer* peer)
    ...
    public static readonly (uint Table, string Name, uint Rva)[] Bindings = {
        (0x01FACAB0, "_G", 0x015E6E40),
        ...
    };
}
```

All values are RVAs (add the module base at runtime).

## How it works

1. **PE parse** — sections, image base, exception data directory. Chained unwind entries are
   folded into their parent so every address maps to one function.
2. **Strings** — every NUL-terminated printable run in `.rdata` / `.data`.
3. **Xrefs** — one linear pass over `.text` for `lea r64,[rip+disp32]` and `call rel32`.
   Each `lea` that lands on a string is attributed to the enclosing function, which makes
   "the function that references string X" an O(1) lookup.
4. **Recipes** — `recipes.inl` holds one line per offset (see below).
5. **Lua tables** — runs of `{const char* name, lua_CFunction fn}` pairs whose function
   pointer is a real function start.
6. **Writers** — `offsets.h` and `offsets.cs`, then the drift check.

## Recipes

```cpp
STR("SendPacket", "SendPacket(int type, std::string* text, ENetPeer* peer)", "Bad peer", true, P_UNIQUE, V(), V()),
STR("AnimTimeParser", "first instantiation", "targetVariableName", true, P_LOWEST, V(), V("offsetVariableName")),
CALLEE("RendererConditionParser", "state-machine <Condition> evaluation", "StateMachineTransitions", "Condition"),
SPECIAL("GetApp", "", K_GETAPP),
```

- `STR(name, comment, anchor, exact, pick, V(also...), V(notalso...))` — the function that
  references `anchor` (`exact` = whole string or substring). `pick` breaks ties when several
  functions reference it: `P_UNIQUE` (fail), `P_LOWEST` / `P_HIGHEST` (address),
  `P_SMALLEST` / `P_LARGEST` (function size). `also` / `notalso` are extra strings the
  function must / must not reference.
- `CALLEE(name, comment, parent, anchor)` — the function called by `parent` that references
  `anchor`.
- `SPECIAL(name, comment, kind)` — pattern based accessors (`GetApp` is the most-called
  `mov rax,[rip+x]; ret` leaf, the others are built on top of it) with their struct offsets
  derived from the code.

When an update breaks a recipe, run with `-v`: the candidates are listed with size, caller
count and the strings they use, so a new anchor or a `V(...)` discriminator is usually a
one-line change. Adding a new offset is one more line; output order is list order.

## Verification

- 2026-09-09 build: 109 / 109 offsets and 39 binding tables. Cross-checked against an
  independent capstone-based analysis with zero mismatches; the drift against the previous
  hand-made offsets file is locally constant with a single genuine linker reorder; the
  generated header compiles; repeated runs are byte-identical.
- 2023-03-14 build (three and a half years older): 72 / 109 without any change to the
  recipes, 5 of them through fallback entries. The rest are features or log strings that did
  not exist back then, so they are reported as `NOT FOUND` rather than guessed.

Several entries in `recipes.inl` share a name: they are fallbacks tried in order, which is
how the mapper survives a string being reworded in one build.

## Türkçe kısa özet

Dump alınmış `Growtopia.exe`'yi ver, `offsets.h` ve `offsets.cs` her sürümde otomatik üretilsin:

```bat
gtmapper.exe gt-dumped.exe
```

Dosyalar exe'nin yanına yazılır; eski `offsets.h` varsa önce onunla karşılaştırılıp özet
basılır. Paketli `gt.exe` çalışmaz, önce dump gerekir. Bir tarif kırılırsa `-v` ile adayları
görüp `recipes.inl` içinde tek satır değiştirmek yeterlidir. Derlemek için `build.bat`.

## Disclaimer

Research and interoperability tooling. Not affiliated with or endorsed by Ubisoft or the
Growtopia team.
