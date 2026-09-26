/*
 *  Reverse-engineering helpers for the debugger and the agent: disassembly, stack and call-chain
 *  reconstruction, function-call tracing, DOS API logging, register writes and a scratch area
 *  for injected code. Everything here runs on the emulation thread.
 */
#ifndef DOSBOX_DEBUG_RE_H
#define DOSBOX_DEBUG_RE_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

struct RE_DisasmLine {
    uint16_t seg = 0;
    uint32_t off = 0;
    uint32_t linear = 0;
    std::string bytes; // hex, space separated
    std::string text;
};

// Disassemble `count` instructions starting at seg:off (seg is a real-mode segment or a selector).
bool RE_Disassemble(uint16_t seg, uint32_t off, unsigned count, std::vector<RE_DisasmLine>* out, std::string* error);

struct RE_StackWord {
    uint32_t offset = 0; // SP-relative address (SS:offset)
    uint32_t value = 0;
};

struct RE_StackFrame {
    std::string source;   // "bp" (frame-pointer chain) or "scan" (return address found on the stack)
    bool far_return = false;
    uint32_t stack_offset = 0; // where the return address lives (SS:offset)
    uint16_t return_cs = 0;
    uint32_t return_ip = 0;
    uint16_t call_cs = 0;      // the CALL instruction that pushed it
    uint32_t call_ip = 0;
    std::string call_text;
    bool has_target = false;   // direct calls: the called function
    uint16_t target_cs = 0;
    uint32_t target_ip = 0;
};

struct RE_StackInfo {
    uint16_t ss = 0;
    uint32_t sp = 0;
    uint32_t bp = 0;
    bool big = false; // 32-bit stack
    uint16_t cs = 0;
    uint32_t ip = 0;
    std::vector<RE_StackWord> words;
    std::vector<RE_StackFrame> frames;
};

bool RE_GetStack(unsigned word_count, RE_StackInfo* info, std::string* error);
std::string RE_FormatStack(const RE_StackInfo& info);

// ---- function-call tracing ----

struct RE_CallTraceOptions {
    bool has_trigger = false;   // start when execution reaches trigger_seg:trigger_off
    uint16_t trigger_seg = 0;
    uint32_t trigger_off = 0;
    uint32_t max_events = 100000;
    bool include_interrupts = true; // software INTs (INT 21h etc.) as events
    bool include_irq = false;       // calls made inside hardware interrupt handlers
    bool stop_on_return = true;     // finish when the starting function returns
    bool break_on_end = false;      // enter the debugger when the trace finishes
};

struct RE_CallEvent {
    uint64_t seq = 0;
    double emulated_ms = 0;
    char kind = 'C';        // C call, R return, I software interrupt, Q hardware interrupt/exception
    bool far_call = false;
    uint16_t depth = 0;
    uint16_t site_cs = 0;   // instruction that called / returned / interrupted
    uint32_t site_ip = 0;
    uint16_t target_cs = 0; // callee, return destination, or interrupt vector number in target_ip
    uint32_t target_ip = 0;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0, esi = 0, edi = 0, ebp = 0, esp = 0;
    uint16_t ds = 0, es = 0;
};

struct RE_CallFunction {
    uint16_t cs = 0;
    uint32_t ip = 0;
    uint32_t calls = 0;
    uint32_t callers = 0;   // distinct call sites
    uint16_t min_depth = 0;
    uint64_t first_seq = 0;
};

struct RE_CallTraceStatus {
    bool armed = false;     // waiting for the trigger
    bool active = false;    // recording
    bool finished = false;
    std::string end_reason;
    uint64_t events = 0;
    uint32_t depth = 0;
    uint32_t functions = 0;
};

extern bool re_calltrace_hook; // cheap per-instruction test

bool RE_CallTraceStart(const RE_CallTraceOptions& options, std::string* error);
void RE_CallTraceStop(const char* reason);
void RE_CallTraceGetStatus(RE_CallTraceStatus* status);
// Events with seq > cursor, oldest first.
void RE_CallTraceRead(uint64_t cursor, size_t limit, std::vector<RE_CallEvent>* out);
void RE_CallTraceFunctions(std::vector<RE_CallFunction>* out);
std::string RE_FormatCallEvent(const RE_CallEvent& event);
bool RE_CallTraceOnInstruction(void); // true: enter the debugger now
void RE_CallTraceOnInterrupt(unsigned num, unsigned type, uint32_t oldeip);

// ---- DOS API log (INT 21h) ----

struct RE_DosEvent {
    uint64_t seq = 0;
    double emulated_ms = 0;
    uint16_t caller_cs = 0;
    uint16_t caller_ip = 0;
    uint8_t ah = 0, al = 0;
    uint16_t bx = 0, cx = 0, dx = 0, si = 0, di = 0, ds = 0, es = 0;
    std::string function; // e.g. "read"
    std::string detail;   // e.g. "PIRATES.FIL @0x1200 +0x0400 -> 1A2B:0000"
};

extern bool re_doslog_hook;

void RE_DosLogStart(void);
void RE_DosLogStop(void);
bool RE_DosLogActive(void);
void RE_DosLogRead(uint64_t cursor, size_t limit, std::vector<RE_DosEvent>* out);
std::string RE_FormatDosEvent(const RE_DosEvent& event);
void RE_DosLogInt21(void); // called at the top of the INT 21h handler

// ---- registers and code injection ----

// names: eax..esp, ax..sp, eip, ip, flags/eflags, cs/ds/es/fs/gs/ss (segments: real/V86 mode only).
bool RE_SetRegisters(const std::vector<std::pair<std::string, uint32_t> >& registers, std::string* error);

// A block of guest memory reserved for injected code (inside the ROM BIOS area, so the guest
// cannot overwrite it; write it with physical-address pokes). Allocated on first use.
bool RE_GetScratch(uint16_t* seg, uint16_t* off, uint32_t* size, std::string* error);

#endif
