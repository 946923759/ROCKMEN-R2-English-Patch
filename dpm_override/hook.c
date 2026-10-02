/*
 * hmm.dll proxy + DPM loose-file override hook for ROCKMEN R2.exe
 * (verified against ROCKMEN R2.exe sha256 938c8160a610d441692370b2fbb7aa20b844a42f9a59615fcd91495915908dde,
 *  imagebase 0x400000, non-relocatable 32-bit build)
 *
 * WHY THIS EXISTS
 * ----------------
 * The game's resource loader always looks a requested filename up in the
 * mounted data.dpm archive's in-memory directory table FIRST, and only
 * falls back to a plain disk fopen(name) for names NOT present in that
 * table. That means simply dropping a translated loose file next to the
 * exe does nothing on its own -- the packed copy inside data.dpm always
 * wins.
 *
 * This DLL patches the "find name in dpm directory" routine at runtime:
 * if a same-named file exists on disk, we force the lookup to report
 * "not found", so the game's own existing fallback code paths
 * transparently take over and load our loose file instead -- with the
 * correct size, no reimplementation of the read path needed.
 *
 * Two runtimes are supported, auto-detected by verifying the target
 * prologue bytes before anything is written:
 *   - ROCKMEN R2.exe (old hsp3hg): lookup sub_426670, Borland EAX-arg
 *     convention, MessageBoxA IAT slot 0x4B72E4
 *   - newer hsp3hg.exe runtime:   lookup sub_453C60, plain __cdecl,
 *     MessageBoxA IAT slot 0x4C12E8
 * If neither target matches (unknown build), no patching happens and the
 * DLL degrades to a pure hmm.dll proxy instead of crashing the loader.
 *
 * INSTALL
 * -------
 *   1. Rename the game's real "hmm.dll" to "hmm_orig.dll"
 *   2. Build this file to "hmm.dll" (see build.bat) and drop it next to the exe
 *   3. Place translated files (event_s_1.txt, etc.) directly next to the exe,
 *      using the exact original filenames
 *
 * The game loads hmm.dll dynamically via LoadLibrary (HSP's #uselib), so
 * proxying it is a safe, minimally invasive injection point that doesn't
 * touch the exe on disk at all.
 *
 * A second, unrelated patch lives here too: *label_025 in start.hsp calls
 * `dialog "(fullscreen y/n prompt, Japanese text)", 2` on every launch,
 * which HSP's hsp3hg runtime implements as a plain imported
 * USER32!MessageBoxA call (IAT slot at 0x4B72E4, verified in IDA -- no
 * in-house dialog routine).
 * We patch that IAT slot to point at MessageBoxA_Hook, which recognizes
 * the fullscreen-prompt text by its CP932 byte pattern and returns IDYES
 * immediately without ever showing a window; every other MessageBoxA call
 * (HSP error boxes, etc.) is passed through untouched to the real API.
 */
#include <windows.h>
#include <string.h>

// Whether to hook the message box and disable the fullscreen prompt
// 1 = hooked, 0 = not hooked
#define HOOK_MSGBOX 1
// Change this to IDYES or IDNO if you want fullscreen or not.
#define FULLSCREEN IDNO

/* ------------------------------------------------------------------ */
/* 1. Override check                                                   */
/* ------------------------------------------------------------------ */

/* Returns nonzero if a loose override file exists for `name` right next
 * to the running exe (i.e. in the process current directory). */
static int HasOverride(const char *name)
{
    DWORD attrs = GetFileAttributesA(name);
    return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

/* Called from the asm shim below. Contract:
 *   return -1  -> pretend "not found in archive" (game falls back to real fopen(name))
 *   return  0  -> not overridden, run the original archive lookup normally
 */
int __cdecl DpmOverrideCheck(char *name)
{
    if (HasOverride(name))
        return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* 2. Runtime inline hook of the dpm-directory lookup                   */
/* ------------------------------------------------------------------ */

/* Per-runtime targets. The byte signatures are the exact prologues of the
 * lookup functions, so we never patch an unknown build by mistake. */
#define OLD_LOOKUP_ADDR  0x00426670u  /* ROCKMEN R2.exe: sub_426670 */
#define OLD_PATCH_LEN    14
static const unsigned char g_oldLookupSig[OLD_PATCH_LEN] = {
    0x81, 0xEC, 0x04, 0x01, 0x00, 0x00, 0x53, 0x55, 0x56, 0x33, 0xED, 0x57, 0x8B, 0xF8
};

#define NEW_LOOKUP_ADDR  0x00453C60u  /* hsp3hg.exe: sub_453C60 (__cdecl) */
#define NEW_PATCH_LEN    12
static const unsigned char g_newLookupSig[NEW_PATCH_LEN] = {
    0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x04, 0x01, 0x00, 0x00, 0x53, 0x56, 0x57
};

#define TRAMP_EXTRA 5                 /* space for the jmp back */

static unsigned char g_origBytes[OLD_PATCH_LEN];
void *g_pTrampoline = 0;              /* old-exe trampoline, used by the asm shim */

typedef int (__cdecl *fnLookup)(char *name);
static fnLookup g_newTrampoline = 0;  /* new-runtime trampoline, called directly */

void Hook_LookupEntry(void);          /* old-exe asm shim, see below */

/* Returns nonzero only if `len` bytes at `addr` are committed/readable and
 * match `sig`. Safe to call on addresses that may not exist in this process. */
static int VerifyBytes(DWORD addr, const unsigned char *sig, int len)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void *)addr, &mbi, sizeof(mbi)))
        return 0;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        return 0;
    return memcmp((void *)addr, sig, len) == 0;
}

static void *BuildTrampoline(DWORD target, const unsigned char *orig, int len)
{
    unsigned char *tramp = (unsigned char *)VirtualAlloc(
        NULL, len + TRAMP_EXTRA, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    /* re-emit the original bytes we're about to overwrite */
    for (int i = 0; i < len; i++)
        tramp[i] = orig[i];

    /* jmp back to right after the patched region */
    DWORD relTarget = (target + len) - ((DWORD)tramp + len + 5);
    tramp[len] = 0xE9;
    *(DWORD *)(tramp + len + 1) = relTarget;

    return tramp;
}

static void PatchJump(DWORD target, void *hookFn, int len)
{
    unsigned char *p = (unsigned char *)target;
    DWORD oldProtect;

    VirtualProtect(p, len, PAGE_EXECUTE_READWRITE, &oldProtect);
    p[0] = 0xE9;
    *(DWORD *)(p + 1) = (DWORD)hookFn - (target + 5);
    for (int i = 5; i < len; i++)
        p[i] = 0x90; /* nop padding */
    VirtualProtect(p, len, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), p, len);
}

/* New-runtime (hsp3hg.exe) hook: sub_453C60 is a normal __cdecl function
 * taking the filename on the stack, so a plain C function works -- no
 * register shuffling needed. */
static int __cdecl LookupHook_New(char *name)
{
    if (HasOverride(name))
        return -1;
    return g_newTrampoline(name);
}

static void InstallHook(void)
{
    if (VerifyBytes(OLD_LOOKUP_ADDR, g_oldLookupSig, OLD_PATCH_LEN))
    {
        for (int i = 0; i < OLD_PATCH_LEN; i++)
            g_origBytes[i] = ((unsigned char *)OLD_LOOKUP_ADDR)[i];
        g_pTrampoline = BuildTrampoline(OLD_LOOKUP_ADDR, g_origBytes, OLD_PATCH_LEN);
        PatchJump(OLD_LOOKUP_ADDR, Hook_LookupEntry, OLD_PATCH_LEN);
    }
    else if (VerifyBytes(NEW_LOOKUP_ADDR, g_newLookupSig, NEW_PATCH_LEN))
    {
        unsigned char orig[NEW_PATCH_LEN];
        for (int i = 0; i < NEW_PATCH_LEN; i++)
            orig[i] = ((unsigned char *)NEW_LOOKUP_ADDR)[i];
        g_newTrampoline = (fnLookup)BuildTrampoline(NEW_LOOKUP_ADDR, orig, NEW_PATCH_LEN);
        PatchJump(NEW_LOOKUP_ADDR, LookupHook_New, NEW_PATCH_LEN);
    }
    /* unknown build: leave the loader untouched, proxying still works */
}

/* sub_426670 receives its single argument in EAX and returns its result
 * in EAX too (Borland-style register convention). This tiny shim adapts
 * that to our normal cdecl DpmOverrideCheck(char*), then either returns
 * -1 directly (override found) or falls into the trampoline that runs
 * the untouched original lookup code. */
void __declspec(naked) Hook_LookupEntry(void)
{
    __asm {
        push eax                       ; keep filename to restore into eax later
        push eax                       ; cdecl arg for DpmOverrideCheck
        call DpmOverrideCheck
        add esp, 4
        test eax, eax
        jz not_overridden
        add esp, 4                     ; override found: discard saved filename, keep eax=-1
        ret
    not_overridden:
        pop eax                        ; not overridden: restore filename into eax
        jmp dword ptr [g_pTrampoline]
    }
}

#if HOOK_MSGBOX == 1
/* ------------------------------------------------------------------ */
/* 3. Auto-answer the fullscreen prompt (IAT patch of MessageBoxA)      */
/* ------------------------------------------------------------------ */

#define MSGBOXA_IAT_OLD  0x004B72E4u  /* ROCKMEN R2.exe import slot */
#define MSGBOXA_IAT_NEW  0x004C12E8u  /* hsp3hg.exe import slot */

/* CP932 bytes for the Japanese word "full screen" -- unique substring of
 * the fullscreen prompt text, matched instead of the whole string to stay
 * resilient to any surrounding punctuation/whitespace differences. */
static const unsigned char g_fullscreenMarker[] = {
    0x83, 0x74, 0x83, 0x8B, 0x83, 0x58, 0x83, 0x4E, 0x83, 0x8A, 0x81, 0x5B, 0x83, 0x93
};

typedef int (WINAPI *fnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
static fnMessageBoxA g_realMessageBoxA = NULL;

static int ContainsFullscreenMarker(const char *text)
{
    size_t markerLen = sizeof(g_fullscreenMarker);
    size_t len, i;

    if (!text)
        return 0;
    len = strlen(text);
    if (len < markerLen)
        return 0;

    for (i = 0; i + markerLen <= len; i++)
    {
        if (memcmp(text + i, g_fullscreenMarker, markerLen) == 0)
            return 1;
    }
    return 0;
}

static int WINAPI MessageBoxA_Hook(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    if (ContainsFullscreenMarker(lpText))
        return FULLSCREEN;
    return g_realMessageBoxA(hWnd, lpText, lpCaption, uType);
}

static void InstallMessageBoxHook(void)
{
    static const DWORD slots[] = { MSGBOXA_IAT_OLD, MSGBOXA_IAT_NEW };
    void *real = (void *)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    DWORD oldProtect;
    int i;

    if (!real)
        return;

    for (i = 0; i < sizeof(slots) / sizeof(slots[0]); i++)
    {
        void **iatSlot = (void **)slots[i];
        MEMORY_BASIC_INFORMATION mbi;

        /* only patch a slot that is mapped AND currently holds the real
         * MessageBoxA pointer -- anything else means this is a different
         * build and the address must not be touched */
        if (!VirtualQuery(iatSlot, &mbi, sizeof(mbi)))
            continue;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            continue;
        if (*iatSlot != real)
            continue;

        VirtualProtect(iatSlot, sizeof(void *), PAGE_EXECUTE_READWRITE, &oldProtect);
        g_realMessageBoxA = (fnMessageBoxA)*iatSlot;
        *iatSlot = (void *)MessageBoxA_Hook;
        VirtualProtect(iatSlot, sizeof(void *), oldProtect, &oldProtect);
        return;
    }
}
#endif

/* ------------------------------------------------------------------ */
/* 4. hmm.dll export forwarding (loaded from the renamed hmm_orig.dll)  */
/* ------------------------------------------------------------------ */

static HMODULE g_hReal = NULL;

typedef int (__stdcall *fn4)(int, int, int, int);

static fn4 Resolve(const char *decoratedName)
{
    return (fn4)GetProcAddress(g_hReal, decoratedName);
}

#define FORWARD(cname, decorated)                                    \
    int __stdcall cname(int a, int b, int c, int d)                  \
    {                                                                 \
        static fn4 real = 0;                                         \
        if (!real) real = Resolve(decorated);                        \
        return real ? real(a, b, c, d) : 0;                          \
    }

FORWARD(HMMINIT_fwd,        "_HMMINIT@16")
FORWARD(HMMEND_fwd,         "_HMMEND@16")
FORWARD(DSEND_fwd,          "_DSEND@16")
FORWARD(DSLOADFNAME_fwd,    "_DSLOADFNAME@16")
FORWARD(DSOGGLOADFNAME_fwd, "_DSOGGLOADFNAME@16")
FORWARD(DSPLAY_fwd,         "_DSPLAY@16")
FORWARD(DSSTOP_fwd,         "_DSSTOP@16")
FORWARD(DSSETVOLUME_fwd,    "_DSSETVOLUME@16")
FORWARD(DIINIT_fwd,         "_DIINIT@16")
FORWARD(DIGETJOYNUM_fwd,    "_DIGETJOYNUM@16")
FORWARD(DIGETJOYSTATE_fwd,  "_DIGETJOYSTATE@16")
FORWARD(HMMBITCHECK_fwd,    "_HMMBITCHECK@16")
FORWARD(HMMGETFPS_fwd,      "_HMMGETFPS@16")

/* ------------------------------------------------------------------ */
/* 5. Entry point                                                       */
/* ------------------------------------------------------------------ */

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinst);
        g_hReal = LoadLibraryA("hmm_orig.dll");
        InstallHook();
#if HOOK_MSGBOX == 1
        InstallMessageBoxHook();
#endif
    }
    return TRUE;
}
