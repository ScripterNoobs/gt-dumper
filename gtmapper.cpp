// gtmapper.cpp - Growtopia (x64) offset mapper
//
// Finds the functions listed in recipes.inl inside a dumped/unpacked Growtopia
// executable and regenerates offsets.h / offsets.cs.  No external dependencies.
//
//   build:  build.bat                     (MSVC, C++17)
//   usage:  gtmapper.exe <gt-dumped.exe> [-o <outdir>] [--verify <old offsets.h>] [-v]
//
// How it works
//   1. PE parse: sections, image base, exception directory (RUNTIME_FUNCTION table).
//      The packer wipes the .pdata *section* but the data directory still points at
//      an intact copy, so function boundaries come from the directory (fallback: .pdata).
//   2. Strings: every NUL terminated printable run in .rdata/.data.
//   3. Xrefs: linear scan of .text for  lea r64,[rip+disp32]  and  call rel32.
//      Each LEA that lands on a string is attributed to the enclosing function.
//   4. Recipes: "the function that references string X" (+ tie-break rules),
//      "the callee of F that references X", and a few pattern based accessors
//      (GetApp / GetClient / GetPacketProcessor / GetLocalAvatar).
//   5. Lua binding tables: runs of {const char* name, lua_CFunction fn} pairs.
//   6. Writers for offsets.h and offsets.cs (same layout as the hand-maintained files).
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

// ---------------------------------------------------------------- helpers
uint16_t rd16(const uint8_t* p) { uint16_t v; memcpy(&v, p, 2); return v; }
uint32_t rd32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }
int32_t  rdi32(const uint8_t* p) { int32_t v; memcpy(&v, p, 4); return v; }
uint64_t rd64(const uint8_t* p) { uint64_t v; memcpy(&v, p, 8); return v; }
bool isPrintable(uint8_t c) { return (c >= 0x20 && c <= 0x7e) || c == '\t' || c == '\n' || c == '\r'; }

std::string hex(uint32_t v) { char b[32]; snprintf(b, sizeof b, "%08X", v); return b; }

std::string escapeC(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        if (c == '\\') o += "\\\\";
        else if (c == '"') o += "\\\"";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else o += (char)c;
    }
    return o;
}

struct Section {
    std::string name;
    uint32_t va = 0, vsize = 0, raw = 0, rawsize = 0, chars = 0;
    uint32_t end() const { return va + std::max(vsize, rawsize); }
};

// ---------------------------------------------------------------- PE image
class Image {
public:
    std::vector<uint8_t> d;
    uint64_t base = 0;
    uint32_t sizeOfImage = 0, entry = 0, timestamp = 0, checksum = 0;
    std::vector<Section> secs;
    const Section* text = nullptr;
    const Section* rdata = nullptr;
    const Section* data = nullptr;
    uint32_t ddExcRva = 0, ddExcSize = 0;

    bool load(const std::string& path, std::string& err) {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) { err = "cannot open " + path; return false; }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        d.resize((size_t)sz);
        if (fread(d.data(), 1, (size_t)sz, f) != (size_t)sz) { fclose(f); err = "read error"; return false; }
        fclose(f);
        if (d.size() < 0x40 || rd16(d.data()) != 0x5A4D) { err = "not an MZ file"; return false; }
        uint32_t e = rd32(&d[0x3C]);
        if ((size_t)e + 24 > d.size() || rd32(&d[e]) != 0x00004550) { err = "bad PE header"; return false; }
        uint16_t nsec = rd16(&d[e + 6]);
        timestamp = rd32(&d[e + 8]);
        uint16_t optsz = rd16(&d[e + 20]);
        if ((size_t)e + 24 + optsz + 40u * nsec > d.size()) { err = "truncated headers"; return false; }
        const uint8_t* opt = &d[e + 24];
        if (rd16(opt) != 0x20B) { err = "not a PE32+ (x64) image"; return false; }
        entry = rd32(opt + 16);
        base = rd64(opt + 24);
        sizeOfImage = rd32(opt + 56);
        checksum = rd32(opt + 64);
        uint32_t ndd = rd32(opt + 108);
        if (ndd > 3) { ddExcRva = rd32(opt + 112 + 8 * 3); ddExcSize = rd32(opt + 116 + 8 * 3); }
        const uint8_t* s = opt + optsz;
        for (int i = 0; i < nsec; i++, s += 40) {
            Section sc;
            char nm[9] = {0};
            memcpy(nm, s, 8);
            sc.name = nm;
            sc.vsize = rd32(s + 8); sc.va = rd32(s + 12); sc.rawsize = rd32(s + 16); sc.raw = rd32(s + 20); sc.chars = rd32(s + 36);
            secs.push_back(sc);
        }
        text = sec(".text"); rdata = sec(".rdata"); data = sec(".data");
        if (!text || !rdata || !data) { err = "missing .text/.rdata/.data section"; return false; }
        return true;
    }
    const Section* sec(const char* name) const {
        for (auto& s : secs) if (s.name == name) return &s;
        return nullptr;
    }
    const Section* secOf(uint32_t rva) const {
        for (auto& s : secs) if (rva >= s.va && rva < s.end()) return &s;
        return nullptr;
    }
    // file offset of an rva, -1 when the rva has no backing bytes in the file
    int64_t off(uint32_t rva) const {
        const Section* s = secOf(rva);
        if (!s) return -1;
        uint32_t rel = rva - s->va;
        if (rel >= s->rawsize) return -1;
        uint64_t o = (uint64_t)s->raw + rel;
        return o < d.size() ? (int64_t)o : -1;
    }
    const uint8_t* ptr(uint32_t rva, size_t need) const {
        int64_t o = off(rva);
        if (o < 0 || (uint64_t)o + need > d.size()) return nullptr;
        return &d[(size_t)o];
    }
    bool inText(uint32_t rva) const { return rva >= text->va && rva < text->end(); }
    bool inStrSec(uint32_t rva) const {
        return (rva >= rdata->va && rva < rdata->end()) || (rva >= data->va && rva < data->end());
    }
};

// ---------------------------------------------------------------- function table (RUNTIME_FUNCTION)
class FuncTable {
public:
    struct Range { uint32_t begin, end, primary; };
    std::vector<Range> ranges;        // sorted by begin, chained entries mapped to their parent
    std::vector<uint32_t> prims;      // sorted primary function starts
    std::unordered_map<uint32_t, uint32_t> primEnd;
    std::string source;

    bool build(const Image& img) {
        std::vector<std::array<uint32_t, 3>> ents;
        auto parse = [&](uint32_t rva, uint32_t size) {
            const uint8_t* p = img.ptr(rva, size);
            if (!p) return;
            for (uint32_t i = 0; i + 12 <= size; i += 12) {
                uint32_t b = rd32(p + i), e = rd32(p + i + 4), u = rd32(p + i + 8);
                if (!b && !e) break;
                if (!img.inText(b) || e <= b) continue;
                ents.push_back({b, e, u});
            }
        };
        auto sane = [&]() {
            if (ents.size() < 100) return false;
            for (size_t i = 1; i < ents.size(); i++) if (ents[i][0] <= ents[i - 1][0]) return false;
            return true;
        };
        parse(img.ddExcRva, img.ddExcSize);
        source = "exception data directory";
        if (!sane()) {
            ents.clear();
            if (const Section* p = img.sec(".pdata")) parse(p->va, p->vsize);
            source = ".pdata section";
            if (!sane()) return false;
        }
        std::unordered_map<uint32_t, uint32_t> chain;
        for (auto& e : ents) {
            const uint8_t* ui = img.ptr(e[2], 4);
            if (!ui) continue;
            uint8_t flags = ui[0] >> 3;
            if (flags & 4) {  // UNW_FLAG_CHAININFO -> parent RUNTIME_FUNCTION follows the codes
                uint32_t cnt = ui[2];
                uint32_t ci = e[2] + 4 + ((cnt + 1) & ~1u) * 2;
                const uint8_t* cp = img.ptr(ci, 12);
                if (cp) chain[e[0]] = rd32(cp);
            } else {
                prims.push_back(e[0]);
            }
        }
        std::sort(prims.begin(), prims.end());
        prims.erase(std::unique(prims.begin(), prims.end()), prims.end());
        for (auto& e : ents) {
            uint32_t p = e[0];
            for (int guard = 0; guard < 16; guard++) {
                auto it = chain.find(p);
                if (it == chain.end()) break;
                p = it->second;
            }
            ranges.push_back({e[0], e[1], p});
            uint32_t& me = primEnd[p];
            me = std::max(me, e[1]);
        }
        std::sort(ranges.begin(), ranges.end(), [](const Range& a, const Range& b) { return a.begin < b.begin; });
        return true;
    }
    uint32_t funcOf(uint32_t rva) const {
        auto it = std::upper_bound(ranges.begin(), ranges.end(), rva, [](uint32_t v, const Range& r) { return v < r.begin; });
        if (it == ranges.begin()) return 0;
        --it;
        return (rva >= it->begin && rva < it->end) ? it->primary : 0;
    }
    bool isFunc(uint32_t rva) const { return std::binary_search(prims.begin(), prims.end(), rva); }
    uint32_t sizeOf(uint32_t f) const {
        auto it = primEnd.find(f);
        return it == primEnd.end() ? 0 : it->second - f;
    }
};

// ---------------------------------------------------------------- strings + xrefs
class Analysis {
public:
    const Image& img;
    const FuncTable& ft;
    std::unordered_map<uint32_t, std::string> strCache;                                   // rva -> string starting there
    std::unordered_map<uint32_t, std::vector<uint32_t>> leaRefs;                          // target -> lea insns
    std::unordered_map<uint32_t, std::vector<uint32_t>> callRefs;                         // function -> call insns
    std::unordered_map<uint32_t, uint32_t> callCountAny;                                  // any E8 target -> count
    std::unordered_map<uint32_t, std::vector<std::pair<uint32_t, uint32_t>>> funcCalls;   // func -> (insn, target)
    std::unordered_map<uint32_t, std::vector<std::pair<uint32_t, const std::string*>>> funcStrs;  // func -> (insn, str)
    std::unordered_map<uint32_t, std::vector<std::pair<uint32_t, uint32_t>>> funcLeas;              // func -> (insn, target) all LEAs
    std::unordered_map<std::string, std::vector<uint32_t>> owners;                        // string -> funcs referencing it
    size_t leaCount = 0, callCount = 0;

    Analysis(const Image& i, const FuncTable& f) : img(i), ft(f) {}

    const std::string* strAt(uint32_t rva) {
        auto it = strCache.find(rva);
        if (it != strCache.end()) return it->second.empty() ? nullptr : &it->second;
        std::string s;
        const uint8_t* p = img.ptr(rva, 1);
        if (p) {
            int64_t o = img.off(rva);
            size_t maxn = std::min<size_t>(1024, img.d.size() - (size_t)o);
            size_t n = 0;
            while (n < maxn && p[n] && isPrintable(p[n])) n++;
            if (n > 0 && n < maxn && p[n] == 0) s.assign((const char*)p, n);
        }
        auto& slot = strCache[rva];
        slot = s;
        return slot.empty() ? nullptr : &slot;
    }

    void run() {
        const Section& t = *img.text;
        size_t n = std::min<size_t>(t.rawsize, img.d.size() - t.raw);
        const uint8_t* p = &img.d[t.raw];
        for (size_t i = 0; i + 8 <= n; i++) {
            uint8_t b0 = p[i];
            if ((b0 == 0x48 || b0 == 0x4C) && p[i + 1] == 0x8D && (p[i + 2] & 0xC7) == 0x05) {
                uint32_t insn = t.va + (uint32_t)i;
                uint32_t tgt = insn + 7 + rdi32(p + i + 3);
                if (tgt < img.sizeOfImage) { leaRefs[tgt].push_back(insn); leaCount++; }
            }
            if (b0 == 0xE8) {
                uint32_t insn = t.va + (uint32_t)i;
                uint32_t tgt = insn + 5 + rdi32(p + i + 1);
                if (img.inText(tgt)) {
                    callCountAny[tgt]++;
                    if (ft.isFunc(tgt)) { callRefs[tgt].push_back(insn); callCount++; }
                }
            }
        }
        for (auto& kv : leaRefs)
            for (uint32_t insn : kv.second) {
                uint32_t f = ft.funcOf(insn);
                if (f) funcLeas[f].push_back({insn, kv.first});
            }
        for (auto& kv : funcLeas) std::sort(kv.second.begin(), kv.second.end());
        for (auto& kv : leaRefs) {
            if (!img.inStrSec(kv.first)) continue;
            const std::string* s = strAt(kv.first);
            if (!s) continue;
            for (uint32_t insn : kv.second) {
                uint32_t f = ft.funcOf(insn);
                if (!f) continue;
                funcStrs[f].push_back({insn, s});
                owners[*s].push_back(f);
            }
        }
        for (auto& kv : funcStrs) std::sort(kv.second.begin(), kv.second.end());
        for (auto& kv : owners) {
            std::sort(kv.second.begin(), kv.second.end());
            kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
        }
        for (auto& kv : callRefs)
            for (uint32_t insn : kv.second) {
                uint32_t f = ft.funcOf(insn);
                if (f) funcCalls[f].push_back({insn, kv.first});
            }
        for (auto& kv : funcCalls) std::sort(kv.second.begin(), kv.second.end());
    }

    bool funcRefs(uint32_t f, const std::string& s, bool exact = true) const {
        auto it = funcStrs.find(f);
        if (it == funcStrs.end()) return false;
        for (auto& e : it->second) {
            if (exact ? (*e.second == s) : (e.second->find(s) != std::string::npos)) return true;
        }
        return false;
    }
    std::vector<uint32_t> ownersOf(const std::string& needle, bool exact) const {
        std::vector<uint32_t> out;
        if (exact) {
            auto it = owners.find(needle);
            if (it != owners.end()) out = it->second;
        } else {
            for (auto& kv : owners)
                if (kv.first.find(needle) != std::string::npos) out.insert(out.end(), kv.second.begin(), kv.second.end());
            std::sort(out.begin(), out.end());
            out.erase(std::unique(out.begin(), out.end()), out.end());
        }
        return out;
    }
    std::vector<uint32_t> callers(uint32_t f) const {
        std::set<uint32_t> s;
        auto it = callRefs.find(f);
        if (it != callRefs.end())
            for (uint32_t insn : it->second) { uint32_t c = ft.funcOf(insn); if (c) s.insert(c); }
        return std::vector<uint32_t>(s.begin(), s.end());
    }
    uint32_t anyCalls(uint32_t f) const {
        auto it = callCountAny.find(f);
        return it == callCountAny.end() ? 0 : it->second;
    }
    // masked pattern search over .text ("48 8B 05 ?? ?? ?? ?? C3")
    std::vector<uint32_t> findPattern(const char* pat) const {
        std::vector<int> bytes;
        for (const char* p = pat; *p;) {
            while (*p == ' ') p++;
            if (!*p) break;
            if (p[0] == '?') { bytes.push_back(-1); p += (p[1] == '?') ? 2 : 1; }
            else { bytes.push_back((int)strtoul(std::string(p, 2).c_str(), nullptr, 16)); p += 2; }
        }
        std::vector<uint32_t> out;
        const Section& t = *img.text;
        size_t n = std::min<size_t>(t.rawsize, img.d.size() - t.raw);
        const uint8_t* d = &img.d[t.raw];
        for (size_t i = 0; i + bytes.size() <= n; i++) {
            bool ok = true;
            for (size_t j = 0; j < bytes.size(); j++)
                if (bytes[j] >= 0 && d[i + j] != (uint8_t)bytes[j]) { ok = false; break; }
            if (ok) out.push_back(t.va + (uint32_t)i);
        }
        return out;
    }
};

// ---------------------------------------------------------------- recipes
enum Kind {
    K_STR, K_CALLEE, K_GETAPP, K_GETCLIENT, K_GETPP, K_GETLA,
    K_PATTERN,        // byte signature; exact=true: match is the function start, exact=false: match is `E8 rel32`, resolve it
    K_CALLAFTER,      // first call after the LEA of the anchor string inside its owner function
    K_LARGEST,        // largest callee (by size) of `parent`
    K_NTHCALL,        // arg-th call target (address order) inside `parent`
    K_ALIAS,          // same address as `parent`
    K_GETAPP_LAZY,    // the lazy-init GetApp variant (allocates App on first use)
    K_GETAPP_TAILACC, // `sub rsp,28; call GetApp; mov rcx,rax; add rsp,28; jmp helper` accessor, most called
    K_VTABLE,         // vtable found in `parent` (a constructor); result = slot `arg`; validated by needle-recipe at slot `arg2`
    K_FIELD           // derive a struct offset, see resolveField() (mode = arg, needle = restricting recipe)
};
enum Pick { P_UNIQUE, P_LOWEST, P_HIGHEST, P_SMALLEST, P_LARGEST };

struct Recipe {
    const char* name;
    const char* comment;
    Kind kind;
    const char* needle;                 // K_STR / K_CALLEE: the anchor string
    bool exact;                         // whole-string match (true) or substring (false)
    Pick pick;                          // tie-break when several functions reference the anchor
    std::vector<const char*> also;      // function must also reference all of these
    std::vector<const char*> notalso;   // ... and none of these
    const char* parent;                 // K_CALLEE: name of the recipe whose callees are searched
    int arg;                            // K_VTABLE slot / K_NTHCALL index / K_FIELD mode
    int arg2;                           // K_VTABLE validator slot
};

#include "recipes.inl"

struct Result {
    uint32_t rva = 0;
    bool ok = false;
    std::string note;                   // extra info appended to the comment
    std::vector<uint32_t> cands;
    const Recipe* recipe = nullptr;     // the entry that resolved it (or the first entry when unresolved)
    int attempts = 0;
};

struct Resolver {
    const Image& img;
    const FuncTable& ft;
    const Analysis& an;
    std::map<std::string, Result> results;
    std::vector<std::string> order;     // unique names in first-occurrence order (= output order)
    bool verbose;

    Resolver(const Image& i, const FuncTable& f, const Analysis& a, bool v) : img(i), ft(f), an(a), verbose(v) {}

    uint32_t get(const char* name) const {
        auto it = results.find(name);
        return (it != results.end() && it->second.ok) ? it->second.rva : 0;
    }

    Result resolveStr(const Recipe& r) {
        Result res;
        std::vector<uint32_t> c = an.ownersOf(r.needle, r.exact);
        std::vector<uint32_t> f;
        for (uint32_t x : c) {
            bool ok = true;
            for (const char* a : r.also) if (!an.funcRefs(x, a)) { ok = false; break; }
            for (const char* nname : r.notalso) if (ok && an.funcRefs(x, nname)) { ok = false; break; }
            if (ok) f.push_back(x);
        }
        std::sort(f.begin(), f.end());
        res.cands = f;
        if (f.empty()) { res.note = "anchor string not referenced by any function"; return res; }
        switch (r.pick) {
        case P_UNIQUE:
            if (f.size() == 1) { res.rva = f[0]; res.ok = true; }
            else res.note = "ambiguous (" + std::to_string(f.size()) + " candidates)";
            break;
        case P_LOWEST:  res.rva = f.front(); res.ok = true; break;
        case P_HIGHEST: res.rva = f.back(); res.ok = true; break;
        case P_SMALLEST: {
            uint32_t best = f[0];
            for (uint32_t x : f) if (ft.sizeOf(x) < ft.sizeOf(best)) best = x;
            res.rva = best; res.ok = true; break;
        }
        case P_LARGEST: {
            uint32_t best = f[0];
            for (uint32_t x : f) if (ft.sizeOf(x) > ft.sizeOf(best)) best = x;
            res.rva = best; res.ok = true; break;
        }
        }
        return res;
    }

    Result resolveCallee(const Recipe& r) {
        Result res;
        uint32_t p = get(r.parent);
        if (!p) { res.note = std::string("parent ") + r.parent + " unresolved"; return res; }
        std::set<uint32_t> c;
        auto it = an.funcCalls.find(p);
        if (it != an.funcCalls.end())
            for (auto& e : it->second)
                if (an.funcRefs(e.second, r.needle, r.exact)) c.insert(e.second);
        res.cands.assign(c.begin(), c.end());
        if (c.size() == 1) { res.rva = *c.begin(); res.ok = true; }
        else res.note = c.empty() ? "no callee references the anchor" : "ambiguous callees";
        return res;
    }

    // GetApp: `mov rax,[rip+g_pApp]; ret` - the most called 8-byte leaf in the image
    Result resolveGetApp() {
        Result res;
        uint32_t best = 0, bestN = 0;
        for (uint32_t rva : an.findPattern("48 8B 05 ?? ?? ?? ?? C3")) {
            uint32_t n = an.anyCalls(rva);
            if (n > bestN) { bestN = n; best = rva; }
        }
        if (best && bestN > 100) { res.rva = best; res.ok = true; res.note = "leaf without unwind data; " + std::to_string(bestN) + " call sites"; }
        else res.note = "no dominant `mov rax,[rip+x]; ret` leaf found";
        return res;
    }

    // GetClient: `sub rsp,28; call GetApp; mov rax,[rax+disp]; add rsp,28; ret`, called from ProcessTankUpdatePacket
    Result resolveGetClient() {
        Result res;
        uint32_t ga = get("GetApp");
        if (!ga) { res.note = "GetApp unresolved"; return res; }
        uint32_t ptup = get("ProcessTankUpdatePacket");
        struct C { uint32_t rva; int32_t disp; uint32_t n; bool fromPtup; };
        std::vector<C> c;
        for (uint32_t rva : an.findPattern("48 83 EC 28 E8 ?? ?? ?? ?? 48 8B 80 ?? ?? ?? ?? 48 83 C4 28 C3")) {
            const uint8_t* p = img.ptr(rva, 21);
            if (!p) continue;
            if (rva + 9 + rdi32(p + 5) != ga) continue;
            C e{rva, rdi32(p + 12), an.anyCalls(rva), false};
            for (uint32_t k : an.callers(rva)) if (k == ptup) e.fromPtup = true;
            c.push_back(e);
        }
        for (auto& e : c) res.cands.push_back(e.rva);
        const C* sel = nullptr;
        int nPtup = 0;
        for (auto& e : c) if (e.fromPtup) { nPtup++; sel = &e; }
        if (nPtup != 1) {
            sel = nullptr;
            if (c.size() == 1) sel = &c[0];
            else for (auto& e : c) if (!sel || e.n > sel->n) sel = &e;
        }
        if (sel) {
            res.rva = sel->rva; res.ok = true;
            char b[64]; snprintf(b, sizeof b, "kAppClientOffset = 0x%X (derived)", sel->disp);
            res.note = b;
        } else res.note = "no GetApp-based accessor found";
        return res;
    }

    // GetPacketProcessor: `sub rsp,28; call GetApp; mov rcx,rax; call helper; add rsp,28; ret`, helper = `mov rax,[rcx+disp]; ret`
    Result resolveGetPP() {
        Result res;
        uint32_t ga = get("GetApp");
        if (!ga) { res.note = "GetApp unresolved"; return res; }
        uint32_t best = 0, bestN = 0; int32_t bestDisp = 0;
        for (uint32_t rva : an.findPattern("48 83 EC 28 E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 83 C4 28 C3")) {
            const uint8_t* p = img.ptr(rva, 22);
            if (!p) continue;
            if (rva + 9 + rdi32(p + 5) != ga) continue;
            uint32_t helper = rva + 17 + rdi32(p + 13);
            const uint8_t* h = img.ptr(helper, 8);
            if (!h || h[0] != 0x48 || h[1] != 0x8B || h[2] != 0x81 || h[7] != 0xC3) continue;
            res.cands.push_back(rva);
            uint32_t n = an.anyCalls(rva);
            if (n > bestN) { bestN = n; best = rva; bestDisp = rdi32(h + 3); }
        }
        if (best) {
            res.rva = best; res.ok = true;
            char b[64]; snprintf(b, sizeof b, "kAppPacketProcessorOffset = 0x%X (derived)", bestDisp);
            res.note = b;
        } else res.note = "no GetApp/helper accessor found";
        return res;
    }

    // GetLocalAvatar: the getter most often called as `call GetPacketProcessor; mov rcx,rax; call X` with X = `mov rax,[rcx+disp]; ret`
    Result resolveGetLA() {
        Result res;
        uint32_t pp = get("GetPacketProcessor");
        if (!pp) { res.note = "GetPacketProcessor unresolved"; return res; }
        std::map<uint32_t, std::pair<uint32_t, int32_t>> cnt;  // y -> (count, disp)
        auto it = an.callRefs.find(pp);
        if (it != an.callRefs.end()) {
            for (uint32_t insn : it->second) {
                const uint8_t* b = img.ptr(insn + 5, 8);
                if (!b || b[0] != 0x48 || b[1] != 0x8B || b[2] != 0xC8 || b[3] != 0xE8) continue;
                uint32_t y = insn + 13 + rdi32(b + 4);
                const uint8_t* yb = img.ptr(y, 8);
                if (!yb || yb[0] != 0x48 || yb[1] != 0x8B || yb[2] != 0x81 || yb[7] != 0xC3) continue;
                auto& e = cnt[y];
                e.first++;
                e.second = rdi32(yb + 3);
            }
        }
        uint32_t best = 0, bestN = 0; int32_t disp = 0;
        for (auto& kv : cnt) {
            res.cands.push_back(kv.first);
            if (kv.second.first > bestN) { bestN = kv.second.first; best = kv.first; disp = kv.second.second; }
        }
        if (best) {
            res.rva = best; res.ok = true;
            char b[80]; snprintf(b, sizeof b, "kPacketProcessorLocalAvatarOffset = 0x%X (derived)", disp);
            res.note = b;
        } else res.note = "no getter follows GetPacketProcessor call sites";
        return res;
    }

    std::vector<uint32_t> pickAll(const Recipe& r, std::vector<uint32_t> f, Result& res) {
        std::sort(f.begin(), f.end());
        f.erase(std::unique(f.begin(), f.end()), f.end());
        res.cands = f;
        if (f.empty()) return f;
        switch (r.pick) {
        case P_UNIQUE: if (f.size() == 1) { res.rva = f[0]; res.ok = true; } else res.note = "ambiguous (" + std::to_string(f.size()) + " candidates)"; break;
        case P_LOWEST: res.rva = f.front(); res.ok = true; break;
        case P_HIGHEST: res.rva = f.back(); res.ok = true; break;
        case P_SMALLEST: { uint32_t b = f[0]; for (uint32_t x : f) if (ft.sizeOf(x) < ft.sizeOf(b)) b = x; res.rva = b; res.ok = true; break; }
        case P_LARGEST: { uint32_t b = f[0]; for (uint32_t x : f) if (ft.sizeOf(x) > ft.sizeOf(b)) b = x; res.rva = b; res.ok = true; break; }
        }
        return f;
    }

    // byte signature; candidates must be function starts (or leafs without unwind info)
    Result resolvePattern(const Recipe& r) {
        Result res;
        std::vector<uint32_t> c;
        for (uint32_t m : an.findPattern(r.needle)) {
            uint32_t f = m;
            if (!r.exact) {
                const uint8_t* p = img.ptr(m, 5);
                if (!p || p[0] != 0xE8) continue;
                f = m + 5 + rdi32(p + 1);
            }
            if (!img.inText(f)) continue;
            if (!ft.isFunc(f) && ft.funcOf(f) != 0) continue;
            c.push_back(f);
        }
        if (c.empty()) res.note = "signature not found";
        pickAll(r, c, res);
        return res;
    }

    // first call after the LEA of the anchor string
    Result resolveCallAfter(const Recipe& r) {
        Result res;
        std::vector<uint32_t> c;
        for (uint32_t f : an.ownersOf(r.needle, r.exact)) {
            bool ok = true;
            for (const char* a : r.also) if (!an.funcRefs(f, a)) { ok = false; break; }
            for (const char* n : r.notalso) if (ok && an.funcRefs(f, n)) { ok = false; break; }
            if (!ok) continue;
            auto it = an.funcStrs.find(f);
            if (it == an.funcStrs.end()) continue;
            for (auto& e : it->second) {
                bool hit = r.exact ? (*e.second == r.needle) : (e.second->find(r.needle) != std::string::npos);
                if (!hit) continue;
                const uint8_t* p = img.ptr(e.first + 7, 80);
                if (!p) continue;
                for (int k = 0; k < 75; k++) {
                    if (p[k] != 0xE8) continue;
                    uint32_t tgt = e.first + 7 + k + 5 + rdi32(p + k + 1);
                    if (img.inText(tgt) && (ft.isFunc(tgt) || ft.funcOf(tgt) == 0)) { c.push_back(tgt); break; }
                }
                break;
            }
        }
        if (c.empty()) res.note = "no call follows the anchor string";
        pickAll(r, c, res);
        return res;
    }

    Result resolveLargest(const Recipe& r) {
        Result res;
        uint32_t p = get(r.parent);
        if (!p) { res.note = std::string("parent ") + r.parent + " unresolved"; return res; }
        uint32_t best = 0;
        auto it = an.funcCalls.find(p);
        if (it != an.funcCalls.end())
            for (auto& e : it->second) if (!best || ft.sizeOf(e.second) > ft.sizeOf(best)) best = e.second;
        if (best) { res.rva = best; res.ok = true; res.cands.push_back(best); } else res.note = "parent has no callees";
        return res;
    }

    Result resolveNthCall(const Recipe& r) {
        Result res;
        uint32_t p = get(r.parent);
        if (!p) { res.note = std::string("parent ") + r.parent + " unresolved"; return res; }
        auto it = an.funcCalls.find(p);
        if (it == an.funcCalls.end() || (size_t)r.arg >= it->second.size()) { res.note = "parent has too few calls"; return res; }
        res.rva = it->second[r.arg].second; res.ok = true; res.cands.push_back(res.rva);
        return res;
    }

    Result resolveAlias(const Recipe& r) {
        Result res;
        uint32_t p = get(r.parent);
        if (!p) { res.note = std::string("parent ") + r.parent + " unresolved"; return res; }
        res.rva = p; res.ok = true;
        return res;
    }

    uint32_t appGlobal() {
        uint32_t ga = get("GetApp");
        const uint8_t* p = ga ? img.ptr(ga, 8) : nullptr;
        return p ? ga + 7 + rdi32(p + 3) : 0;
    }

    // small function starting with `mov rax,[rip+g_pApp]` that also calls something (operator new + ctor)
    Result resolveGetAppLazy() {
        Result res;
        uint32_t g = appGlobal();
        if (!g) { res.note = "GetApp unresolved"; return res; }
        uint32_t best = 0, bestN = 0;
        for (uint32_t m : an.findPattern("48 8B 05 ?? ?? ?? ??")) {
            const uint8_t* p = img.ptr(m, 7);
            if (!p || m + 7 + rdi32(p + 3) != g) continue;
            uint32_t f = ft.funcOf(m);
            if (!f || m - f > 8 || ft.sizeOf(f) > 96) continue;
            auto it = an.funcCalls.find(f);
            if (it == an.funcCalls.end() || it->second.empty()) continue;
            res.cands.push_back(f);
            uint32_t n = (uint32_t)an.callers(f).size();
            if (n > bestN) { bestN = n; best = f; }
        }
        if (best) { res.rva = best; res.ok = true; res.note = "lazy-init variant of GetApp"; } else res.note = "no lazy GetApp found";
        return res;
    }

    // `sub rsp,28; call GetApp; mov rcx,rax; add rsp,28; jmp helper`, helper = `mov rax,[rcx+disp32]; ret`
    Result resolveGetAppTailAcc(const Recipe& r) {
        Result res;
        uint32_t ga = get("GetApp");
        if (!ga) { res.note = "GetApp unresolved"; return res; }
        uint32_t best = 0, bestN = 0; int32_t bestDisp = 0;
        for (uint32_t m : an.findPattern("48 83 EC 28 E8 ?? ?? ?? ?? 48 8B C8 48 83 C4 28 E9 ?? ?? ?? ??")) {
            const uint8_t* p = img.ptr(m, 21);
            if (!p || m + 9 + rdi32(p + 5) != ga) continue;
            uint32_t h = m + 21 + rdi32(p + 17);
            const uint8_t* hb = img.ptr(h, 8);
            if (!hb || hb[0] != 0x48 || hb[1] != 0x8B || hb[2] != 0x81 || hb[7] != 0xC3) continue;
            res.cands.push_back(m);
            uint32_t n = an.anyCalls(m);
            if (n > bestN) { bestN = n; best = m; bestDisp = rdi32(hb + 3); }
        }
        if (best) {
            res.rva = best; res.ok = true;
            char b[96]; snprintf(b, sizeof b, "%s = 0x%X (derived)", r.needle && *r.needle ? r.needle : "offset", bestDisp);
            res.note = b;
        } else res.note = "no tail-call accessor on GetApp found";
        return res;
    }

    // vtable = LEA target in the constructor `parent` that is a run of >= 4 .text pointers and whose slot arg2 == needle-recipe
    Result resolveVtable(const Recipe& r) {
        Result res;
        uint32_t ctor = get(r.parent), validator = get(r.needle);
        if (!ctor || !validator) { res.note = "ctor or validator recipe unresolved"; return res; }
        auto it = an.funcLeas.find(ctor);
        if (it == an.funcLeas.end()) { res.note = "ctor has no LEAs"; return res; }
        for (auto& e : it->second) {
            uint32_t vt = e.second;
            if (!(vt >= img.rdata->va && vt < img.rdata->end())) continue;
            std::vector<uint32_t> slots;
            for (int k = 0; k < 64; k++) {
                const uint8_t* p = img.ptr(vt + 8 * k, 8);
                if (!p) break;
                uint64_t q = rd64(p);
                if (q < img.base || q - img.base >= img.sizeOfImage || !img.inText((uint32_t)(q - img.base))) break;
                slots.push_back((uint32_t)(q - img.base));
            }
            if (slots.size() < 4 || (size_t)r.arg2 >= slots.size() || slots[r.arg2] != validator) continue;
            if ((size_t)r.arg >= slots.size()) { res.note = "vtable too small"; return res; }
            res.rva = slots[r.arg]; res.ok = true;
            char b[64]; snprintf(b, sizeof b, "vtable 0x%X slot %d", vt, r.arg);
            res.note = b;
            return res;
        }
        res.note = "no vtable in ctor matches the validator slot";
        return res;
    }

    // struct offset derivation
    //   mode 0: after `call parent`, the most common `mov/lea r64,[rax+disp]` (needle: only sites inside that recipe's function)
    //   mode 1: first `mov rax,[rax+disp32]` inside parent's body
    //   mode 2: like 1 but also `mov rax,[rcx+disp32]`, following a tail `jmp` into a helper
    //   mode 3: most common `lea rcx,[r64+disp32]` in the 24 bytes before calls to parent
    //   mode 4: most common imm32 of `imul r64,r64,imm32` in the 24 bytes after calls to parent
    //   mode 5: before calls to parent: `call GetApp; mov r64,[rax+disp32]` -> disp (the object passed as `this`)
    //   mode 6: like mode 0 but only `mov rcx,[rax+disp32]` (the object passed as `this` right after the accessor)
    //   mode 7: last `mov r8,[r64+disp32]` before calls to parent (3rd argument, e.g. the ENet peer)
    Result resolveField(const Recipe& r) {
        Result res;
        uint32_t p = get(r.parent);
        if (!p) { res.note = std::string("parent ") + r.parent + " unresolved"; return res; }
        std::map<int32_t, int> hist;
        auto add = [&](int32_t v) { hist[v]++; };
        if (r.arg == 0) {
            uint32_t only = (r.needle && *r.needle) ? get(r.needle) : 0;
            if (r.needle && *r.needle && !only) { res.note = std::string("restricting recipe ") + r.needle + " unresolved"; return res; }
            auto it = an.callRefs.find(p);
            if (it != an.callRefs.end())
                for (uint32_t site : it->second) {
                    if (only && ft.funcOf(site) != only) continue;
                    const uint8_t* b = img.ptr(site + 5, 7);
                    if (!b) continue;
                    if ((b[0] == 0x48 || b[0] == 0x4C) && (b[1] == 0x8B || b[1] == 0x8D)) {
                        if ((b[2] & 0xC7) == 0x80) add(rdi32(b + 3));
                        else if ((b[2] & 0xC7) == 0x40) add((int8_t)b[3]);
                    }
                }
        } else if (r.arg == 1 || r.arg == 2) {
            const uint8_t* b = img.ptr(p, 48);
            if (!b) { res.note = "cannot read parent"; return res; }
            bool found = false;
            for (int k = 0; k + 7 <= 48 && !found; k++) {
                if (b[k] == 0x48 && b[k + 1] == 0x8B && (b[k + 2] == 0x80 || (r.arg == 2 && b[k + 2] == 0x81))) { add(rdi32(b + k + 3)); found = true; }
                if (r.arg == 2 && !found && (b[k] == 0xE9 || b[k] == 0xE8)) {   // tail jmp / call into a tiny getter
                    uint32_t h = p + k + 5 + rdi32(b + k + 1);
                    const uint8_t* hb = img.ptr(h, 8);
                    if (hb && hb[0] == 0x48 && hb[1] == 0x8B && (hb[2] == 0x81 || hb[2] == 0x80) && hb[7] == 0xC3) { add(rdi32(hb + 3)); found = true; }
                }
                if (b[k] == 0xC3) break;
            }
        } else if (r.arg == 3) {
            auto it = an.callRefs.find(p);
            if (it != an.callRefs.end())
                for (uint32_t site : it->second) {
                    const uint8_t* b = img.ptr(site - 24, 24);
                    if (!b) continue;
                    for (int k = 0; k + 7 <= 24; k++)
                        if ((b[k] == 0x48 || b[k] == 0x49) && b[k + 1] == 0x8D && (b[k + 2] & 0xF8) == 0x88 && (b[k + 2] & 7) != 4) { add(rdi32(b + k + 3)); break; }
                }
        } else if (r.arg == 4) {
            auto it = an.callRefs.find(p);
            if (it != an.callRefs.end())
                for (uint32_t site : it->second) {
                    const uint8_t* b = img.ptr(site + 5, 24);
                    if (!b) continue;
                    for (int k = 0; k + 7 <= 24; k++)
                        if ((b[k] & 0xF8) == 0x48 && b[k + 1] == 0x69) { add(rdi32(b + k + 3)); break; }
                }
        } else if (r.arg == 5) {
            uint32_t ga = get("GetApp");
            auto it = an.callRefs.find(p);
            if (ga && it != an.callRefs.end())
                for (uint32_t site : it->second) {
                    const int W = 64;
                    const uint8_t* b = img.ptr(site - W, W);
                    if (!b) continue;
                    for (int k = W - 12; k >= 0; k--) {
                        if (b[k] != 0xE8 || site - W + k + 5 + rdi32(b + k + 1) != ga) continue;
                        const uint8_t* n = b + k + 5;
                        if ((n[0] == 0x48 || n[0] == 0x4C) && n[1] == 0x8B && (n[2] & 0xC7) == 0x80) add(rdi32(n + 3));
                        break;
                    }
                }
        } else if (r.arg == 6) {   // mode 6: after `call parent`, only `mov rcx,[rax+disp32]`
            auto it = an.callRefs.find(p);
            if (it != an.callRefs.end())
                for (uint32_t site : it->second) {
                    const uint8_t* b = img.ptr(site + 5, 7);
                    if (b && b[0] == 0x48 && b[1] == 0x8B && b[2] == 0x88) add(rdi32(b + 3));
                }
        } else if (r.arg == 7) {   // mode 7: last `mov r8,[r64+disp32]` in the 32 bytes before calls to parent
            auto it = an.callRefs.find(p);
            if (it != an.callRefs.end())
                for (uint32_t site : it->second) {
                    const uint8_t* b = img.ptr(site - 32, 32);
                    if (!b) continue;
                    int last = -1;
                    for (int k = 0; k + 7 <= 32; k++)
                        if ((b[k] == 0x4C || b[k] == 0x4D) && b[k + 1] == 0x8B && (b[k + 2] & 0xF8) == 0x80 && (b[k + 2] & 7) != 4) last = k;
                    if (last >= 0) add(rdi32(b + last + 3));
                }
        }
        if (hist.empty()) { res.note = "no matching instruction shape"; return res; }
        int32_t best = 0; int bestN = -1, total = 0;
        for (auto& kv : hist) { total += kv.second; if (kv.second > bestN) { bestN = kv.second; best = kv.first; } }
        res.rva = (uint32_t)best; res.ok = true;
        char b[96]; snprintf(b, sizeof b, "derived offset, %d of %d sites agree", bestN, total);
        res.note = b;
        return res;
    }

    void printLine(const char* name, const Result& res, const char* tag) {
        printf("  %-36s %s", name, res.ok ? hex(res.rva).c_str() : "--------");
        if (res.ok) printf("  size %6u  callers %3zu", ft.sizeOf(res.rva), an.callers(res.rva).size());
        if (tag && *tag) printf("  %s", tag);
        if (!res.note.empty()) printf("  [%s]", res.note.c_str());
        if (res.cands.size() > 1 || !res.ok) {
            printf("  cands:");
            for (size_t i = 0; i < res.cands.size() && i < 8; i++) printf(" %X", res.cands[i]);
        }
        printf("\n");
    }

    // Several entries may share a name: they are fallbacks, tried in order until one resolves.
    void run() {
        for (const Recipe& r : kRecipes) {
            if (results.find(r.name) == results.end()) order.push_back(r.name);
            Result& cur = results[r.name];
            if (cur.ok) continue;
            Result res;
            switch (r.kind) {
            case K_STR: res = resolveStr(r); break;
            case K_CALLEE: res = resolveCallee(r); break;
            case K_GETAPP: res = resolveGetApp(); break;
            case K_GETCLIENT: res = resolveGetClient(); break;
            case K_GETPP: res = resolveGetPP(); break;
            case K_GETLA: res = resolveGetLA(); break;
            case K_PATTERN: res = resolvePattern(r); break;
            case K_CALLAFTER: res = resolveCallAfter(r); break;
            case K_LARGEST: res = resolveLargest(r); break;
            case K_NTHCALL: res = resolveNthCall(r); break;
            case K_ALIAS: res = resolveAlias(r); break;
            case K_GETAPP_LAZY: res = resolveGetAppLazy(); break;
            case K_GETAPP_TAILACC: res = resolveGetAppTailAcc(r); break;
            case K_VTABLE: res = resolveVtable(r); break;
            case K_FIELD: res = resolveField(r); break;
            }
            res.attempts = cur.attempts + 1;
            res.recipe = res.ok || cur.recipe == nullptr ? &r : cur.recipe;
            if (!res.ok && cur.attempts > 0) res.note = cur.note + " / fallback " + std::to_string(res.attempts) + ": " + res.note;
            if (res.ok && res.attempts > 1) res.note = (res.note.empty() ? "" : res.note + "; ") + "via fallback recipe " + std::to_string(res.attempts);
            cur = res;
            if (verbose) printLine(r.name, res, res.attempts > 1 ? "(fallback)" : "");
        }
        if (!verbose)
            for (const std::string& n : order)
                if (!results[n].ok) printLine(n.c_str(), results[n], "");
    }
};

// ---------------------------------------------------------------- Lua binding tables
struct LuaTable {
    uint32_t rva;
    std::vector<std::pair<std::string, uint32_t>> rows;
};

std::vector<LuaTable> findLuaTables(const Image& img, const FuncTable& ft, Analysis& an) {
    std::vector<LuaTable> out;
    auto entry = [&](uint32_t p, std::string& name, uint32_t& fn) -> bool {
        const uint8_t* b = img.ptr(p, 16);
        if (!b) return false;
        uint64_t q0 = rd64(b), q1 = rd64(b + 8);
        if (q0 <= img.base || q1 <= img.base) return false;
        uint64_t r0 = q0 - img.base, r1 = q1 - img.base;
        if (r0 >= img.sizeOfImage || r1 >= img.sizeOfImage) return false;
        if (!img.inStrSec((uint32_t)r0) || !img.inText((uint32_t)r1)) return false;
        if (!ft.isFunc((uint32_t)r1)) return false;
        const std::string* s = an.strAt((uint32_t)r0);
        if (!s || s->size() > 40) return false;
        for (unsigned char c : *s) if (c < 0x20) return false;
        name = *s;
        fn = (uint32_t)r1;
        return true;
    };
    for (const Section* sec : {img.rdata, img.data}) {
        uint32_t p = sec->va, end = sec->va + std::min(sec->vsize, sec->rawsize);
        while (p + 16 <= end) {
            std::string name; uint32_t fn;
            if (!entry(p, name, fn)) { p += 8; continue; }
            LuaTable t; t.rva = p;
            uint32_t q = p;
            while (q + 16 <= end && entry(q, name, fn)) { t.rows.push_back({name, fn}); q += 16; }
            if (t.rows.size() >= 3) out.push_back(t);
            p = t.rows.size() >= 3 ? q : p + 8;
        }
    }
    return out;
}

// ---------------------------------------------------------------- output
uint64_t fnv1a(const void* p, size_t n, uint64_t h = 1469598103934665603ULL) {
    const uint8_t* b = (const uint8_t*)p;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 1099511628211ULL; }
    return h;
}

std::string buildHash(const Image& img) {
    uint64_t h = fnv1a(&img.timestamp, 4);
    h = fnv1a(&img.sizeOfImage, 4, h);
    h = fnv1a(&img.entry, 4, h);
    h = fnv1a(&img.checksum, 4, h);
    for (auto& s : img.secs) { h = fnv1a(s.name.data(), s.name.size(), h); h = fnv1a(&s.va, 4, h); h = fnv1a(&s.vsize, 4, h); }
    char b[32]; snprintf(b, sizeof b, "%016llx", (unsigned long long)h);
    return b;
}

std::string utcNow() {
    time_t t = time(nullptr);
    char b[64]; strftime(b, sizeof b, "%Y-%m-%d %H:%M:%SZ", gmtime(&t));
    return b;
}
std::string peTime(uint32_t ts) {
    time_t t = (time_t)ts;
    char b[64]; strftime(b, sizeof b, "%Y-%m-%d %H:%M:%SZ", gmtime(&t));
    return b;
}

std::string commentFor(const Recipe& r, const Result& res) {
    std::string c = r.comment ? r.comment : "";
    if (!res.ok) c = (c.empty() ? "" : c + " ") + "!! NOT FOUND: " + res.note;
    else if (!res.note.empty()) c = (c.empty() ? "" : c + "; ") + res.note;
    return c;
}

bool writeHeader(const std::string& path, const Image& img, const Resolver& rs, const std::vector<LuaTable>& tabs) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    fprintf(f, "// Growtopia x64 offsets - generated %s\n", utcNow().c_str());
    fprintf(f, "// image base 0x%llX  build hash %s  (PE timestamp %s)\n", (unsigned long long)img.base, buildHash(img).c_str(), peTime(img.timestamp).c_str());
    fprintf(f, "#pragma once\n#include <cstdint>\nnamespace gt {\n");
    fprintf(f, "    constexpr uint32_t kBuildTimestamp = 0x%08X; // PE TimeDateStamp of the build these offsets belong to\n", img.timestamp);
    for (const std::string& name : rs.order) {
        const Result& res = rs.results.at(name);
        fprintf(f, "    constexpr uintptr_t k%s = 0x%08X; // %s\n", name.c_str(), res.rva, commentFor(*res.recipe, res).c_str());
    }
    fprintf(f, "\n    struct Binding { const char* name; unsigned int rva; };\n");
    fprintf(f, "    struct BindingTable { unsigned int rva; const Binding* rows; int count; };\n");
    for (size_t i = 0; i < tabs.size(); i++) {
        fprintf(f, "    constexpr Binding kBind%zu[] = {\n", i);
        for (auto& row : tabs[i].rows) fprintf(f, "        {\"%s\", 0x%08X},\n", escapeC(row.first).c_str(), row.second);
        fprintf(f, "    };\n");
    }
    fprintf(f, "    constexpr BindingTable kBindingTables[] = {\n");
    for (size_t i = 0; i < tabs.size(); i++) fprintf(f, "        {0x%08X, kBind%zu, %zu},\n", tabs[i].rva, i, tabs[i].rows.size());
    fprintf(f, "    };\n}\n");
    fclose(f);
    return true;
}

bool writeCs(const std::string& path, const Image& img, const Resolver& rs, const std::vector<LuaTable>& tabs) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    fprintf(f, "// Growtopia x64 offsets - generated %s\n", utcNow().c_str());
    fprintf(f, "// image base 0x%llX  build hash %s  (PE timestamp %s)\n", (unsigned long long)img.base, buildHash(img).c_str(), peTime(img.timestamp).c_str());
    fprintf(f, "public static class Offsets {\n");
    fprintf(f, "    public const UInt32 BuildTimestamp = 0x%08X; // PE TimeDateStamp of the build these offsets belong to\n", img.timestamp);
    for (const std::string& name : rs.order) {
        const Result& res = rs.results.at(name);
        fprintf(f, "    public const Int64 %s = 0x%X; // %s\n", name.c_str(), res.rva, commentFor(*res.recipe, res).c_str());
    }
    fprintf(f, "    public static readonly (uint Table, string Name, uint Rva)[] Bindings = {\n");
    for (auto& t : tabs)
        for (auto& row : t.rows) fprintf(f, "        (0x%08X, \"%s\", 0x%08X),\n", t.rva, escapeC(row.first).c_str(), row.second);
    fprintf(f, "    };\n}\n");
    fclose(f);
    return true;
}

// ---------------------------------------------------------------- drift table against a previous offsets.h
typedef std::vector<std::pair<uint32_t, std::string>> OldOffsets;

OldOffsets parseOldOffsets(const std::string& path) {
    OldOffsets old;
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return old;
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        const char* k = strstr(line, "constexpr uintptr_t k");
        if (!k) continue;
        k += strlen("constexpr uintptr_t k");
        const char* e = strchr(k, ' ');
        const char* v = strstr(k, "0x");
        if (!e || !v) continue;
        old.push_back({(uint32_t)strtoul(v, nullptr, 16), std::string(k, e - k)});
    }
    fclose(f);
    std::sort(old.begin(), old.end());
    return old;
}

// Old->new addresses must keep their order and neighbouring deltas must be similar:
// a lone jump in the delta column or many inversions means a recipe latched onto the wrong function.
void printDrift(const std::string& oldPath, bool automatic, const OldOffsets& old, const Resolver& rs, bool verbose) {
    if (old.empty()) { printf("drift check: %s has no k* constants, skipped\n", oldPath.c_str()); return; }
    printf("\n--- drift vs %s%s ---\n", oldPath.c_str(), automatic ? " (previous output, used automatically)" : "");
    uint32_t prevNew = 0; std::string prevName; int inversions = 0, missing = 0, same = 0;
    for (auto& o : old) {
        auto it = rs.results.find(o.second);
        if (it == rs.results.end() || !it->second.ok) {
            printf("  %08X -> --------            %s (not resolved)\n", o.first, o.second.c_str());
            missing++;
            continue;
        }
        uint32_t n = it->second.rva;
        if (n == o.first) same++;
        bool inv = prevNew && n < prevNew;
        if (inv) inversions++;
        if (verbose || inv)
            printf("  %08X -> %08X  %+9lld  %s%s%s\n", o.first, n, (long long)n - (long long)o.first, o.second.c_str(), inv ? "   <-- order inversion vs " : "", inv ? prevName.c_str() : "");
        prevNew = n; prevName = o.second;
    }
    printf("  %zu constants compared: %d unchanged, %d order inversions, %d unresolved%s\n", old.size(), same, inversions, missing,
           verbose ? "" : "  (run with -v for the full table)");
    if (inversions > 3) printf("  WARNING: many inversions - check the recipes of the functions listed above\n");
}

void usage() {
    printf("usage: gtmapper.exe <gt-dumped.exe>           (or: gtmapper.exe -i <gt-dumped.exe>)\n"
           "  writes offsets.h and offsets.cs next to the input exe\n"
           "options:\n"
           "  -o <dir>              write the two files into <dir> instead\n"
           "  --verify <offsets.h>  drift table against an older offsets.h\n"
           "                        (without it an existing offsets.h in the output dir is compared automatically)\n"
           "  -v                    verbose: every recipe with candidates, all Lua tables, full drift table\n");
}

}  // namespace

int main(int argc, char** argv) {
    std::string exe, outdir, verify;
    bool verbose = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if ((a == "-i" || a == "-input" || a == "--input") && i + 1 < argc) exe = argv[++i];
        else if ((a == "-o" || a == "-out" || a == "--out" || a == "-output" || a == "--output") && i + 1 < argc) outdir = argv[++i];
        else if ((a == "--verify" || a == "-verify") && i + 1 < argc) verify = argv[++i];
        else if (a == "-v" || a == "--verbose") verbose = true;
        else if (a == "-h" || a == "--help" || a == "/?") { usage(); return 2; }
        else if (!a.empty() && a[0] != '-' && exe.empty()) exe = a;
        else { printf("unknown argument: %s\n\n", argv[i]); usage(); return 2; }
    }
    if (exe.empty()) { usage(); return 2; }
    if (outdir.empty()) {  // default: next to the input exe
        size_t s = exe.find_last_of("\\/");
        outdir = (s == std::string::npos) ? "." : exe.substr(0, s);
        if (outdir.empty()) outdir = exe.substr(0, 1);  // "\file" or "/file"
    }
    Image img;
    std::string err;
    if (!img.load(exe, err)) { printf("error: %s\n", err.c_str()); return 1; }
    printf("image: %s  (%zu bytes)  base 0x%llX  timestamp %s  build %s\n", exe.c_str(), img.d.size(), (unsigned long long)img.base, peTime(img.timestamp).c_str(), buildHash(img).c_str());
    for (auto& s : img.secs) printf("  %-8s va %08X size %08X\n", s.name.c_str(), s.va, s.vsize);
    if (img.text->rawsize < img.text->vsize / 2) {
        printf("error: .text has no file data - this is the packed executable. Dump the running game (Scylla etc.) and run the mapper on the dump.\n");
        return 1;
    }

    FuncTable ft;
    if (!ft.build(img)) { printf("error: no usable RUNTIME_FUNCTION table (exception directory and .pdata both broken)\n"); return 1; }
    printf("functions: %zu primary (%zu ranges) from %s\n", ft.prims.size(), ft.ranges.size(), ft.source.c_str());

    Analysis an(img, ft);
    an.run();
    printf("xrefs: %zu lea, %zu calls, %zu distinct strings referenced\n", an.leaCount, an.callCount, an.owners.size());

    printf("resolving %zu recipe entries%s\n", std::size(kRecipes), verbose ? "" : " (only problems are listed)");
    Resolver rs(img, ft, an, verbose);
    rs.run();
    size_t okc = 0, viaFallback = 0;
    for (auto& kv : rs.results) if (kv.second.ok) { okc++; if (kv.second.attempts > 1) viaFallback++; }
    printf("resolved %zu / %zu offsets", okc, rs.results.size());
    if (viaFallback) printf(" (%zu via fallback recipes)", viaFallback);
    printf("\n");

    std::vector<LuaTable> tabs = findLuaTables(img, ft, an);
    printf("lua binding tables: %zu\n", tabs.size());
    if (verbose)
        for (size_t i = 0; i < tabs.size(); i++) {
            printf("  kBind%-2zu %08X n=%2zu ", i, tabs[i].rva, tabs[i].rows.size());
            for (size_t j = 0; j < tabs[i].rows.size() && j < 6; j++) printf("%s%s", j ? "," : "", tabs[i].rows[j].first.c_str());
            printf("\n");
        }

    std::string sep = (outdir.empty() || outdir.back() == '\\' || outdir.back() == '/') ? "" : "\\";
    std::string hPath = outdir + sep + "offsets.h", csPath = outdir + sep + "offsets.cs";

    // drift check input: an explicit --verify file, otherwise the offsets.h we are about to overwrite
    bool autoVerify = false;
    if (verify.empty()) {
        FILE* t = fopen(hPath.c_str(), "rb");
        if (t) { fclose(t); verify = hPath; autoVerify = true; }
    }
    OldOffsets old;
    if (!verify.empty()) {
        old = parseOldOffsets(verify);
        if (old.empty() && !autoVerify) printf("verify: cannot read any k* constants from %s\n", verify.c_str());
    }

    if (!writeHeader(hPath, img, rs, tabs) || !writeCs(csPath, img, rs, tabs)) { printf("error: cannot write output files in %s\n", outdir.c_str()); return 1; }
    printf("wrote %s and %s\n", hPath.c_str(), csPath.c_str());

    if (!old.empty()) printDrift(verify, autoVerify, old, rs, verbose);
    if (okc != rs.results.size()) { printf("WARNING: %zu recipe(s) unresolved - entries written as 0 and marked NOT FOUND\n", rs.results.size() - okc); return 3; }
    return 0;
}
