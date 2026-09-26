/*
 *  Reverse-engineering helpers: disassembly, stack/call-chain reconstruction, function-call
 *  tracing, DOS API logging, register writes and a scratch area for injected code.
 *  Used by the debugger commands STACK / CALLTRACE / DOSLOG and by the agent RPC.
 */
#include "dosbox.h"

#if C_DEBUG
#include "debug_re.h"

#include "bios.h"
#include "control.h"
#include "cpu.h"
#include "debug.h"
#include "dos_inc.h"
#include "mem.h"
#include "paging.h"
#include "pic.h"
#include "regs.h"
#include "setup.h"
#include "debug_inc.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

uint64_t GetAddress(uint16_t seg, uint32_t offset);
bool ChangeRegister(char* const str);
bool IsDebuggerActive(void);

bool re_calltrace_hook = false;
bool re_doslog_hook = false;

namespace {

const uint64_t kNoAddress = ~0ULL;

bool ReadByte(uint32_t linear, uint8_t* value)
{
    return !mem_readb_checked((LinearPt)linear, value); /* *_checked returns true on fault */
}

bool ReadWord(uint32_t linear, uint16_t* value)
{
    uint8_t lo = 0, hi = 0;
    if (!ReadByte(linear, &lo) || !ReadByte(linear + 1, &hi))
        return false;
    *value = (uint16_t)(lo | (hi << 8));
    return true;
}

bool ReadDword(uint32_t linear, uint32_t* value)
{
    uint16_t lo = 0, hi = 0;
    if (!ReadWord(linear, &lo) || !ReadWord(linear + 2, &hi))
        return false;
    *value = (uint32_t)lo | ((uint32_t)hi << 16);
    return true;
}

std::string ReHex(uint32_t value, int width)
{
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%0*X", width, (unsigned)value);
    return buffer;
}

bool CodeIsBig(uint16_t seg)
{
    if (!cpu.pmode || (reg_flags & FLAG_VM))
        return false;
    Descriptor desc;
    if (cpu.gdt.GetDescriptor(seg, desc))
        return desc.saved.seg.big != 0;
    return cpu.code.big;
}

uint32_t CurrentIp(void)
{
    return cpu.code.big ? reg_eip : (uint32_t)reg_ip;
}

uint32_t StackOffset(void)
{
    return cpu.stack.big ? reg_esp : (uint32_t)reg_sp;
}

uint32_t StackLinear(void)
{
    return (uint32_t)SegPhys(ss) + StackOffset();
}

// Decode the opcode after any prefixes. Returns false if memory is unreadable.
bool DecodeOpcode(uint32_t linear, bool code32, uint8_t* opcode, uint8_t* modrm, bool* op32, unsigned* prefix_len)
{
    bool operand32 = code32;
    unsigned index = 0;
    uint8_t byte = 0;
    for (; index < 8; ++index) {
        if (!ReadByte(linear + index, &byte))
            return false;
        if (byte == 0x66) { operand32 = !code32; continue; }
        if (byte == 0x67 || byte == 0x26 || byte == 0x2E || byte == 0x36 || byte == 0x3E ||
            byte == 0x64 || byte == 0x65 || byte == 0xF0 || byte == 0xF2 || byte == 0xF3)
            continue;
        break;
    }
    *opcode = byte;
    *modrm = 0;
    if (byte == 0xFF && !ReadByte(linear + index + 1, modrm))
        return false;
    *op32 = operand32;
    *prefix_len = index;
    return true;
}

bool IsNearCall(uint8_t opcode, uint8_t modrm) { return opcode == 0xE8 || (opcode == 0xFF && ((modrm >> 3) & 7) == 2); }
bool IsFarCall(uint8_t opcode, uint8_t modrm) { return opcode == 0x9A || (opcode == 0xFF && ((modrm >> 3) & 7) == 3); }

// Is there a CALL instruction that ends exactly at seg:ret_ip? Fills call site/target/text.
bool CallBefore(uint16_t seg, uint32_t ret_ip, bool far_return, RE_StackFrame* frame)
{
    const bool code32 = CodeIsBig(seg);
    for (unsigned length = 2; length <= 8; ++length) {
        if (ret_ip < length)
            break;
        const uint32_t call_ip = ret_ip - length;
        const uint64_t linear = GetAddress(seg, call_ip);
        if (linear == kNoAddress)
            continue;
        uint8_t opcode = 0, modrm = 0;
        bool op32 = false;
        unsigned prefixes = 0;
        if (!DecodeOpcode((uint32_t)linear, code32, &opcode, &modrm, &op32, &prefixes))
            continue;
        if (far_return ? !IsFarCall(opcode, modrm) : !IsNearCall(opcode, modrm))
            continue;
        char text[200];
        const Bitu size = DasmI386(text, (PhysPt)linear, call_ip, code32);
        if (size != length)
            continue;
        frame->far_return = far_return;
        frame->return_cs = seg;
        frame->return_ip = ret_ip;
        frame->call_cs = seg;
        frame->call_ip = call_ip;
        frame->call_text = text;
        frame->has_target = false;
        const uint32_t operand = (uint32_t)linear + prefixes + 1;
        if (opcode == 0xE8) {
            uint32_t target = 0;
            if (op32) {
                uint32_t rel = 0;
                if (ReadDword(operand, &rel)) { target = ret_ip + rel; frame->has_target = true; }
            } else {
                uint16_t rel = 0;
                if (ReadWord(operand, &rel)) { target = (ret_ip + rel) & 0xFFFFu; frame->has_target = true; }
            }
            frame->target_cs = seg;
            frame->target_ip = target;
        } else if (opcode == 0x9A) {
            uint16_t off16 = 0, sel = 0;
            uint32_t off32 = 0;
            if (op32 ? ReadDword(operand, &off32) && ReadWord(operand + 4, &sel)
                     : ReadWord(operand, &off16) && ReadWord(operand + 2, &sel)) {
                frame->has_target = true;
                frame->target_cs = sel;
                frame->target_ip = op32 ? off32 : off16;
            }
        }
        return true;
    }
    return false;
}

} // namespace

// ---------------------------------------------------------------- disassembly

bool RE_Disassemble(uint16_t seg, uint32_t off, unsigned count, std::vector<RE_DisasmLine>* out, std::string* error)
{
    out->clear();
    const bool code32 = CodeIsBig(seg);
    uint32_t ip = off;
    for (unsigned index = 0; index < count; ++index) {
        const uint64_t linear = GetAddress(seg, ip);
        if (linear == kNoAddress) {
            if (index == 0) {
                *error = "Address is not mapped";
                return false;
            }
            break;
        }
        char text[200];
        const Bitu size = DasmI386(text, (PhysPt)linear, ip, code32);
        RE_DisasmLine line;
        line.seg = seg;
        line.off = ip;
        line.linear = (uint32_t)linear;
        line.text = text;
        for (Bitu byte_index = 0; byte_index < size; ++byte_index) {
            uint8_t value = 0;
            if (!ReadByte((uint32_t)linear + (uint32_t)byte_index, &value))
                break;
            if (!line.bytes.empty())
                line.bytes += ' ';
            line.bytes += ReHex(value, 2);
        }
        out->push_back(line);
        ip += (uint32_t)(size ? size : 1);
        if (!code32)
            ip &= 0xFFFFu;
    }
    return true;
}

// ---------------------------------------------------------------- stack

bool RE_GetStack(unsigned word_count, RE_StackInfo* info, std::string* error)
{
    (void)error;
    const bool big = cpu.stack.big;
    const uint32_t width = big ? 4u : 2u;
    info->ss = SegValue(ss);
    info->sp = StackOffset();
    info->bp = big ? reg_ebp : reg_bp;
    info->big = big;
    info->cs = SegValue(cs);
    info->ip = CurrentIp();
    info->words.clear();
    info->frames.clear();
    const uint32_t base = (uint32_t)SegPhys(ss);
    const uint32_t mask = big ? 0xFFFFFFFFu : 0xFFFFu;

    for (unsigned index = 0; index < word_count; ++index) {
        const uint32_t offset = (info->sp + index * width) & mask;
        RE_StackWord word;
        word.offset = offset;
        if (big) {
            if (!ReadDword(base + offset, &word.value)) break;
        } else {
            uint16_t value = 0;
            if (!ReadWord(base + offset, &value)) break;
            word.value = value;
        }
        info->words.push_back(word);
    }

    std::map<uint32_t, RE_StackFrame> frames; // by stack offset of the return address
    std::set<uint16_t> code_segments;
    code_segments.insert(info->cs);

    // 1) frame-pointer chain: [BP] = caller's BP, [BP+w] = return IP, [BP+2w] = return CS if far
    uint32_t bp = info->bp;
    uint16_t current_cs = info->cs;
    for (unsigned depth = 0; depth < 64; ++depth) {
        if (bp < info->sp || bp - info->sp > 0x10000u)
            break;
        uint32_t saved_bp = 0, ret_ip = 0, ret_cs = 0;
        if (big) {
            if (!ReadDword(base + bp, &saved_bp) || !ReadDword(base + bp + 4, &ret_ip)) break;
            ReadDword(base + bp + 8, &ret_cs);
        } else {
            uint16_t a = 0, b = 0, c = 0;
            if (!ReadWord(base + ((bp) & mask), &a) || !ReadWord(base + ((bp + 2) & mask), &b)) break;
            ReadWord(base + ((bp + 4) & mask), &c);
            saved_bp = a; ret_ip = b; ret_cs = c;
        }
        RE_StackFrame frame;
        if (!big && CallBefore((uint16_t)ret_cs, ret_ip, true, &frame)) {
            current_cs = (uint16_t)ret_cs;
            code_segments.insert(current_cs);
        } else if (!CallBefore(current_cs, ret_ip, false, &frame)) {
            break;
        }
        frame.source = "bp";
        frame.stack_offset = (bp + width) & mask;
        frames[frame.stack_offset] = frame;
        if (saved_bp <= bp)
            break;
        bp = saved_bp;
    }

    // 2) scan: any stack word that is a return address right after a CALL instruction
    for (size_t index = 0; index < info->words.size(); ++index) {
        const RE_StackWord& word = info->words[index];
        if (frames.count(word.offset))
            continue;
        RE_StackFrame frame;
        bool found = false;
        if (!big && index + 1 < info->words.size() &&
            CallBefore((uint16_t)info->words[index + 1].value, word.value, true, &frame)) {
            found = true;
            code_segments.insert((uint16_t)info->words[index + 1].value);
        }
        if (!found) {
            for (std::set<uint16_t>::const_iterator seg = code_segments.begin(); seg != code_segments.end() && !found; ++seg)
                found = CallBefore(*seg, word.value, false, &frame);
        }
        if (found) {
            frame.source = "scan";
            frame.stack_offset = word.offset;
            frames[word.offset] = frame;
        }
    }
    for (std::map<uint32_t, RE_StackFrame>::const_iterator it = frames.begin(); it != frames.end(); ++it)
        info->frames.push_back(it->second);
    return true;
}

std::string RE_FormatStack(const RE_StackInfo& info)
{
    const int w = info.big ? 8 : 4;
    std::ostringstream out;
    out << "SS:SP=" << ReHex(info.ss, 4) << ":" << ReHex(info.sp, w) << " BP=" << ReHex(info.bp, w)
        << " CS:IP=" << ReHex(info.cs, 4) << ":" << ReHex(info.ip, w) << (info.big ? " (32-bit stack)" : "") << "\n";
    out << "Call chain, innermost first (bp = frame-pointer chain, scan = return address found on stack):\n";
    if (info.frames.empty())
        out << "  (no return addresses recognised)\n";
    unsigned number = 0;
    for (std::vector<RE_StackFrame>::const_iterator frame = info.frames.begin(); frame != info.frames.end(); ++frame) {
        out << "  #" << number++ << " [SS:" << ReHex(frame->stack_offset, w) << "] "
            << (frame->far_return ? "far " : "near") << " ret " << ReHex(frame->return_cs, 4) << ":" << ReHex(frame->return_ip, w)
            << "  from " << ReHex(frame->call_cs, 4) << ":" << ReHex(frame->call_ip, w) << " " << frame->call_text;
        if (frame->has_target)
            out << "  -> " << ReHex(frame->target_cs, 4) << ":" << ReHex(frame->target_ip, w);
        out << "  (" << frame->source << ")\n";
    }
    out << "Stack:\n";
    for (size_t index = 0; index < info.words.size(); ++index) {
        if (index % 8 == 0)
            out << (index ? "\n" : "") << "  SS:" << ReHex(info.words[index].offset, w) << " ";
        out << " " << ReHex(info.words[index].value, w);
    }
    out << "\n";
    return out.str();
}

// ---------------------------------------------------------------- call tracing

namespace {

struct TraceFrame {
    char kind;          // 'C' call, 'I' software interrupt, 'Q' hardware interrupt / exception
    uint32_t sp;        // linear stack address holding the return address
};

struct FunctionStats {
    uint16_t cs = 0;
    uint32_t ip = 0;
    uint32_t calls = 0;
    std::set<uint32_t> callers;
    uint16_t min_depth = 0xFFFF;
    uint64_t first_seq = 0;
};

struct TraceState {
    RE_CallTraceOptions options;
    bool armed = false;
    bool active = false;
    bool finished = false;
    bool break_pending = false;
    std::string end_reason;
    uint32_t trigger_linear = 0;
    uint32_t root_sp = 0;
    std::vector<TraceFrame> frames;
    unsigned irq_depth = 0;
    bool pending_call = false;
    bool pending_far = false;
    uint16_t pending_cs = 0;
    uint32_t pending_ip = 0;
    uint32_t pending_sp = 0;
    bool pending_int = false;
    char pending_int_kind = 'I';
    std::vector<RE_CallEvent> events;
    uint64_t next_seq = 1;
    std::map<uint32_t, FunctionStats> functions;
    std::string saved_core;
    bool core_changed = false;
};

TraceState trace;

unsigned CallDepth(void)
{
    unsigned depth = 0;
    for (std::vector<TraceFrame>::const_iterator frame = trace.frames.begin(); frame != trace.frames.end(); ++frame)
        if (frame->kind == 'C')
            ++depth;
    return depth;
}

bool Suppressed(void)
{
    return trace.irq_depth > 0 && !trace.options.include_irq;
}

void FillRegisters(RE_CallEvent* event)
{
    event->emulated_ms = (double)PIC_FullIndex();
    event->eax = reg_eax; event->ebx = reg_ebx; event->ecx = reg_ecx; event->edx = reg_edx;
    event->esi = reg_esi; event->edi = reg_edi; event->ebp = reg_ebp; event->esp = reg_esp;
    event->ds = SegValue(ds); event->es = SegValue(es);
}

void Finish(const char* reason);

void Record(RE_CallEvent& event)
{
    event.seq = trace.next_seq++;
    trace.events.push_back(event);
    if (trace.events.size() >= trace.options.max_events)
        Finish("max_events reached");
}

void RestoreCoreEvent(Bitu /*val*/)
{
    if (!trace.core_changed)
        return;
    trace.core_changed = false;
    Section_prop* section = static_cast<Section_prop*>(control->GetSection("cpu"));
    if (section != NULL) {
        std::string line = "core=" + trace.saved_core;
        section->HandleInputline(line);
    }
}

void Finish(const char* reason)
{
    if (trace.finished && !trace.active && !trace.armed)
        return;
    trace.active = false;
    trace.armed = false;
    trace.finished = true;
    trace.end_reason = reason;
    trace.break_pending = trace.options.break_on_end;
    // With break_on_end, stay hooked for one more instruction: the debugger then stops right
    // after the final instruction (e.g. back in the caller once the traced function returned).
    re_calltrace_hook = trace.break_pending;
    // The CPU core may be running right now; switch cores back from the PIC queue instead.
    if (trace.core_changed)
        PIC_AddEvent(RestoreCoreEvent, 0.01);
}

void Activate(uint32_t sp)
{
    trace.armed = false;
    trace.active = true;
    trace.root_sp = sp;
    trace.frames.clear();
    trace.irq_depth = 0;
    trace.pending_call = false;
    trace.pending_int = false;
}

void PopTo(size_t index)
{
    for (size_t pop = trace.frames.size(); pop > index; --pop) {
        if (trace.frames[pop - 1].kind == 'Q' && trace.irq_depth > 0)
            --trace.irq_depth;
    }
    trace.frames.resize(index);
}

} // namespace

bool RE_CallTraceStart(const RE_CallTraceOptions& options, std::string* error)
{
#if C_HEAVY_DEBUG
    if (options.max_events == 0) {
        *error = "max_events must be positive";
        return false;
    }
    if (trace.core_changed)
        RestoreCoreEvent(0);
    trace = TraceState();
    trace.options = options;
    trace.events.reserve(options.max_events < 65536 ? options.max_events : 65536);
    if (options.has_trigger) {
        const uint64_t linear = GetAddress(options.trigger_seg, options.trigger_off);
        if (linear == kNoAddress) {
            *error = "Trigger address is not mapped";
            return false;
        }
        trace.trigger_linear = (uint32_t)linear;
        trace.armed = true;
    } else {
        Activate(StackLinear());
    }
    // Per-instruction hooks only run in the interpreter cores.
    Section_prop* section = static_cast<Section_prop*>(control->GetSection("cpu"));
    if (section != NULL) {
        const std::string core = section->Get_string("core");
        if (core != "normal") {
            trace.saved_core = core;
            trace.core_changed = true;
            std::string line = "core=normal";
            section->HandleInputline(line);
        }
    }
    re_calltrace_hook = true;
    return true;
#else
    (void)options;
    *error = "Call tracing needs a C_HEAVY_DEBUG build";
    return false;
#endif
}

void RE_CallTraceStop(const char* reason)
{
    if (trace.active || trace.armed)
        Finish(reason ? reason : "stopped");
    else if (trace.core_changed)
        RestoreCoreEvent(0);
}

void RE_CallTraceGetStatus(RE_CallTraceStatus* status)
{
    status->armed = trace.armed;
    status->active = trace.active;
    status->finished = trace.finished;
    status->end_reason = trace.end_reason;
    status->events = trace.events.size();
    status->depth = CallDepth();
    status->functions = (uint32_t)trace.functions.size();
}

void RE_CallTraceRead(uint64_t cursor, size_t limit, std::vector<RE_CallEvent>* out)
{
    out->clear();
    for (std::vector<RE_CallEvent>::const_iterator event = trace.events.begin();
         event != trace.events.end() && out->size() < limit; ++event) {
        if (event->seq > cursor)
            out->push_back(*event);
    }
}

void RE_CallTraceFunctions(std::vector<RE_CallFunction>* out)
{
    out->clear();
    for (std::map<uint32_t, FunctionStats>::const_iterator it = trace.functions.begin(); it != trace.functions.end(); ++it) {
        RE_CallFunction function;
        function.cs = it->second.cs;
        function.ip = it->second.ip;
        function.calls = it->second.calls;
        function.callers = (uint32_t)it->second.callers.size();
        function.min_depth = it->second.min_depth;
        function.first_seq = it->second.first_seq;
        out->push_back(function);
    }
}

std::string RE_FormatCallEvent(const RE_CallEvent& event)
{
    std::ostringstream out;
    out << std::string((size_t)(event.depth < 40 ? event.depth : 40) * 2, ' ');
    switch (event.kind) {
    case 'C':
        out << (event.far_call ? "CALLF " : "CALL  ") << ReHex(event.target_cs, 4) << ":" << ReHex(event.target_ip, 4)
            << "  from " << ReHex(event.site_cs, 4) << ":" << ReHex(event.site_ip, 4)
            << "  AX=" << ReHex(event.eax & 0xFFFF, 4) << " BX=" << ReHex(event.ebx & 0xFFFF, 4)
            << " CX=" << ReHex(event.ecx & 0xFFFF, 4) << " DX=" << ReHex(event.edx & 0xFFFF, 4);
        break;
    case 'R':
        out << "RET   to " << ReHex(event.target_cs, 4) << ":" << ReHex(event.target_ip, 4)
            << "  from " << ReHex(event.site_cs, 4) << ":" << ReHex(event.site_ip, 4)
            << "  AX=" << ReHex(event.eax & 0xFFFF, 4) << " DX=" << ReHex(event.edx & 0xFFFF, 4);
        break;
    default:
        out << (event.kind == 'I' ? "INT   " : "IRQ   ") << ReHex(event.target_ip, 2) << "h"
            << "  at " << ReHex(event.site_cs, 4) << ":" << ReHex(event.site_ip, 4)
            << "  AX=" << ReHex(event.eax & 0xFFFF, 4) << " BX=" << ReHex(event.ebx & 0xFFFF, 4)
            << " CX=" << ReHex(event.ecx & 0xFFFF, 4) << " DX=" << ReHex(event.edx & 0xFFFF, 4)
            << " DS=" << ReHex(event.ds, 4) << " ES=" << ReHex(event.es, 4);
        break;
    }
    return out.str();
}

bool RE_CallTraceOnInstruction(void)
{
    if (!trace.active && !trace.armed) {
        re_calltrace_hook = false;
        if (trace.break_pending) {
            trace.break_pending = false;
            DEBUG_EnableDebugger();
            return true;
        }
        return false;
    }
    const uint32_t ip = CurrentIp();
    const uint32_t pc = (uint32_t)SegPhys(cs) + ip;
    const uint32_t sp = StackLinear();

    if (trace.armed) {
        if (pc != trace.trigger_linear)
            return false;
        Activate(sp);
    }

    if (trace.pending_int) {
        TraceFrame frame = { trace.pending_int_kind, sp };
        trace.frames.push_back(frame);
        if (frame.kind == 'Q')
            ++trace.irq_depth;
        trace.pending_int = false;
    }

    if (trace.pending_call && sp == trace.pending_sp) {
        trace.pending_call = false;
        TraceFrame frame = { 'C', sp };
        trace.frames.push_back(frame);
        const unsigned depth = CallDepth();
        FunctionStats& stats = trace.functions[pc];
        if (stats.calls == 0) {
            stats.cs = SegValue(cs);
            stats.ip = ip;
            stats.first_seq = trace.next_seq;
        }
        ++stats.calls;
        stats.callers.insert(((uint32_t)trace.pending_cs << 16) ^ trace.pending_ip);
        if (depth < stats.min_depth)
            stats.min_depth = (uint16_t)depth;
        if (!Suppressed()) {
            RE_CallEvent event;
            event.kind = 'C';
            event.far_call = trace.pending_far;
            event.depth = (uint16_t)depth;
            event.site_cs = trace.pending_cs;
            event.site_ip = trace.pending_ip;
            event.target_cs = SegValue(cs);
            event.target_ip = ip;
            FillRegisters(&event);
            Record(event);
        }
    }
    if (!trace.active)
        return false;

    uint8_t opcode = 0, modrm = 0;
    bool op32 = false;
    unsigned prefixes = 0;
    if (!DecodeOpcode(pc, cpu.code.big, &opcode, &modrm, &op32, &prefixes))
        return false;

    const bool near_call = IsNearCall(opcode, modrm);
    const bool far_call = IsFarCall(opcode, modrm);
    if (near_call || far_call) {
        trace.pending_call = true;
        trace.pending_far = far_call;
        trace.pending_cs = SegValue(cs);
        trace.pending_ip = ip;
        const uint32_t width = op32 ? 4u : 2u;
        trace.pending_sp = sp - (far_call ? 2 * width : width);
        return false;
    }

    const bool ret = opcode == 0xC3 || opcode == 0xC2 || opcode == 0xCB || opcode == 0xCA;
    const bool iret = opcode == 0xCF;
    if (!ret && !iret)
        return false;

    // The frame whose return address sits at SS:SP is the one returning.
    size_t match = trace.frames.size();
    while (match > 0 && trace.frames[match - 1].sp != sp)
        --match;
    if (match > 0) {
        const TraceFrame frame = trace.frames[match - 1];
        const unsigned depth = CallDepth();
        const bool suppressed = Suppressed();
        PopTo(match - 1);
        if (frame.kind == 'C' && !suppressed) {
            RE_CallEvent event;
            event.kind = 'R';
            event.far_call = opcode == 0xCB || opcode == 0xCA;
            event.depth = (uint16_t)depth;
            event.site_cs = SegValue(cs);
            event.site_ip = ip;
            uint16_t ret_ip16 = 0, ret_cs = SegValue(cs);
            ReadWord(sp, &ret_ip16);
            if (event.far_call)
                ReadWord(sp + (op32 ? 4 : 2), &ret_cs);
            uint32_t ret_ip = ret_ip16;
            if (op32)
                ReadDword(sp, &ret_ip);
            event.target_cs = ret_cs;
            event.target_ip = ret_ip;
            FillRegisters(&event);
            Record(event);
        }
    } else if (ret && trace.options.stop_on_return && sp >= trace.root_sp) {
        Finish("starting function returned");
    }
    return false;
}

void RE_CallTraceOnInterrupt(unsigned num, unsigned type, uint32_t oldeip)
{
    if (!re_calltrace_hook || !trace.active)
        return;
    const bool software = (type & CPU_INT_SOFTWARE) != 0;
    trace.pending_int = true;
    trace.pending_int_kind = software ? 'I' : 'Q';
    const bool record = software ? (trace.options.include_interrupts && !Suppressed()) : trace.options.include_irq;
    if (!record)
        return;
    RE_CallEvent event;
    event.kind = software ? 'I' : 'Q';
    event.depth = (uint16_t)CallDepth();
    event.site_cs = SegValue(cs);
    event.site_ip = software && oldeip >= 2 ? oldeip - 2 : oldeip; // INT nn is two bytes
    event.target_cs = 0;
    event.target_ip = num;
    FillRegisters(&event);
    Record(event);
}

// ---------------------------------------------------------------- DOS API log

namespace {

std::vector<RE_DosEvent> dos_events;
uint64_t dos_next_seq = 1;
const size_t kDosLogCapacity = 100000;

std::string ReadString(uint16_t seg, uint16_t off, size_t max, char terminator)
{
    std::string text;
    for (size_t index = 0; index < max; ++index) {
        uint8_t value = 0;
        if (!ReadByte((uint32_t)(seg << 4) + (uint16_t)(off + index), &value) || value == (uint8_t)terminator)
            break;
        text.push_back(value >= 32 && value < 127 ? (char)value : '.');
    }
    return text;
}

std::string HandleName(uint16_t handle, uint32_t* position, bool* has_position)
{
    *has_position = false;
    const uint8_t sfn = RealHandle(handle);
    if (sfn == 0xFF || Files == NULL || Files[sfn] == NULL || !Files[sfn]->IsOpen())
        return "handle " + std::to_string(handle);
    std::string name = Files[sfn]->GetName() ? Files[sfn]->GetName() : "?";
    if ((Files[sfn]->GetInformation() & 0x80) == 0) { /* not a device */
        uint32_t pos = 0;
        if (Files[sfn]->Seek(&pos, DOS_SEEK_CUR)) {
            *position = pos;
            *has_position = true;
        }
    }
    return name + " (#" + std::to_string(handle) + ")";
}

} // namespace

void RE_DosLogStart(void)
{
    dos_events.clear();
    re_doslog_hook = true;
}

void RE_DosLogStop(void)
{
    re_doslog_hook = false;
}

bool RE_DosLogActive(void)
{
    return re_doslog_hook;
}

void RE_DosLogRead(uint64_t cursor, size_t limit, std::vector<RE_DosEvent>* out)
{
    out->clear();
    for (std::vector<RE_DosEvent>::const_iterator event = dos_events.begin();
         event != dos_events.end() && out->size() < limit; ++event) {
        if (event->seq > cursor)
            out->push_back(*event);
    }
}

std::string RE_FormatDosEvent(const RE_DosEvent& event)
{
    std::ostringstream out;
    out << ReHex(event.caller_cs, 4) << ":" << ReHex(event.caller_ip, 4) << "  INT21 AH=" << ReHex(event.ah, 2)
        << " " << event.function;
    if (!event.detail.empty())
        out << "  " << event.detail;
    return out.str();
}

void RE_DosLogInt21(void)
{
    if (!re_doslog_hook)
        return;
    RE_DosEvent event;
    event.seq = dos_next_seq++;
    event.emulated_ms = (double)PIC_FullIndex();
    event.ah = reg_ah; event.al = reg_al;
    event.bx = reg_bx; event.cx = reg_cx; event.dx = reg_dx; event.si = reg_si; event.di = reg_di;
    event.ds = SegValue(ds); event.es = SegValue(es);
    // INT pushed FLAGS, CS, IP: the caller's return address is at SS:SP.
    ReadWord((uint32_t)SegPhys(ss) + reg_sp, &event.caller_ip);
    ReadWord((uint32_t)SegPhys(ss) + reg_sp + 2, &event.caller_cs);

    std::ostringstream detail;
    uint32_t position = 0;
    bool has_position = false;
    const std::string path = ReadString(event.ds, event.dx, 128, 0);
    switch (event.ah) {
    case 0x01: event.function = "read char (echo)"; break;
    case 0x02: event.function = "write char"; detail << "'" << (char)(event.dx & 0xFF) << "'"; break;
    case 0x06: event.function = "direct console io"; break;
    case 0x07: case 0x08: event.function = "read char"; break;
    case 0x09: event.function = "print string"; detail << '"' << ReadString(event.ds, event.dx, 80, '$') << '"'; break;
    case 0x0A: event.function = "buffered input"; break;
    case 0x0B: event.function = "input status"; break;
    case 0x0C: event.function = "flush + input"; break;
    case 0x0E: event.function = "select drive"; detail << (char)('A' + (event.dx & 0xFF)); break;
    case 0x19: event.function = "get drive"; break;
    case 0x1A: event.function = "set DTA"; detail << ReHex(event.ds, 4) << ":" << ReHex(event.dx, 4); break;
    case 0x25: event.function = "set vector"; detail << "INT " << ReHex(event.al, 2) << "h -> " << ReHex(event.ds, 4) << ":" << ReHex(event.dx, 4); break;
    case 0x2A: event.function = "get date"; break;
    case 0x2C: event.function = "get time"; break;
    case 0x30: event.function = "get DOS version"; break;
    case 0x35: event.function = "get vector"; detail << "INT " << ReHex(event.al, 2) << "h"; break;
    case 0x36: event.function = "disk free"; break;
    case 0x39: event.function = "mkdir"; detail << path; break;
    case 0x3A: event.function = "rmdir"; detail << path; break;
    case 0x3B: event.function = "chdir"; detail << path; break;
    case 0x3C: event.function = "create"; detail << path << " attr " << ReHex(event.cx, 2); break;
    case 0x3D: event.function = "open"; detail << path << " mode " << ReHex(event.al, 2); break;
    case 0x3E: event.function = "close"; detail << HandleName(event.bx, &position, &has_position); break;
    case 0x3F:
    case 0x40:
        event.function = event.ah == 0x3F ? "read" : "write";
        detail << HandleName(event.bx, &position, &has_position);
        if (has_position)
            detail << " @0x" << ReHex(position, 1);
        detail << " +0x" << ReHex(event.cx, 1) << (event.ah == 0x3F ? " -> " : " <- ") << ReHex(event.ds, 4) << ":" << ReHex(event.dx, 4);
        break;
    case 0x41: event.function = "delete"; detail << path; break;
    case 0x42: {
        event.function = "seek";
        detail << HandleName(event.bx, &position, &has_position);
        static const char* const methods[] = { "from start", "from current", "from end" };
        detail << " 0x" << ReHex(((uint32_t)event.cx << 16) | event.dx, 1) << " " << (event.al < 3 ? methods[event.al] : "?");
        break;
    }
    case 0x43: event.function = "file attributes"; detail << path; break;
    case 0x44: event.function = "ioctl"; detail << "AL=" << ReHex(event.al, 2) << " handle " << event.bx; break;
    case 0x47: event.function = "get cwd"; break;
    case 0x48: event.function = "alloc memory"; detail << ReHex(event.bx, 4) << " paragraphs"; break;
    case 0x49: event.function = "free memory"; detail << "segment " << ReHex(event.es, 4); break;
    case 0x4A: event.function = "resize memory"; detail << "segment " << ReHex(event.es, 4) << " to " << ReHex(event.bx, 4) << " paragraphs"; break;
    case 0x4B: event.function = "exec"; detail << path << " AL=" << ReHex(event.al, 2); break;
    case 0x4C: event.function = "exit"; detail << "code " << (int)event.al; break;
    case 0x4E: event.function = "find first"; detail << path; break;
    case 0x4F: event.function = "find next"; break;
    case 0x56: event.function = "rename"; detail << path << " -> " << ReadString(event.es, event.di, 128, 0); break;
    case 0x57: event.function = "file date/time"; break;
    case 0x62: event.function = "get PSP"; break;
    case 0x6C: event.function = "extended open"; detail << ReadString(event.ds, event.si, 128, 0) << " mode " << ReHex(event.bx, 4); break;
    default: event.function = "AH=" + ReHex(event.ah, 2) + "h"; break;
    }
    event.detail = detail.str();
    if (dos_events.size() >= kDosLogCapacity)
        dos_events.erase(dos_events.begin(), dos_events.begin() + kDosLogCapacity / 10);
    dos_events.push_back(event);
}

// ---------------------------------------------------------------- registers / injection

bool RE_SetRegisters(const std::vector<std::pair<std::string, uint32_t> >& registers, std::string* error)
{
    if (!IsDebuggerActive()) {
        *error = "The CPU must be stopped in the debugger to change registers";
        return false;
    }
    static const char* const allowed[] = {
        "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP", "EFLAGS",
        "AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP", "IP", "FLAGS",
        "CS", "DS", "ES", "FS", "GS", "SS",
    };
    std::string command;
    for (size_t index = 0; index < registers.size(); ++index) {
        std::string name = registers[index].first;
        for (std::string::iterator it = name.begin(); it != name.end(); ++it)
            *it = (char)toupper((unsigned char)*it);
        bool known = false;
        for (size_t check = 0; check < sizeof(allowed) / sizeof(allowed[0]); ++check)
            known = known || name == allowed[check];
        if (!known) {
            *error = "Unknown register " + registers[index].first;
            return false;
        }
        const bool segment = name == "CS" || name == "DS" || name == "ES" || name == "FS" || name == "GS" || name == "SS";
        if (segment && cpu.pmode && !(reg_flags & FLAG_VM)) {
            *error = "Segment registers can only be changed in real or V86 mode";
            return false;
        }
        /* leading 0: GetHexValue() also accepts register/flag names, and a value such as CF must stay a number */
        if (!command.empty())
            command += " ";
        command += name + " 0" + ReHex(registers[index].second, 1);
    }
    if (command.empty())
        return true;
    std::vector<char> buffer(command.begin(), command.end());
    buffer.push_back('\0');
    if (!ChangeRegister(&buffer[0])) {
        *error = "The debugger rejected the register update";
        return false;
    }
    return true;
}

bool RE_GetScratch(uint16_t* seg, uint16_t* off, uint32_t* size, std::string* error)
{
    static Bitu scratch = 0;
    static uint32_t scratch_size = 0;
    if (scratch_size == 0) {
        static const uint32_t sizes[] = { 4096, 2048, 1024, 512, 256 };
        for (size_t index = 0; index < sizeof(sizes) / sizeof(sizes[0]) && scratch_size == 0; ++index) {
            const Bitu address = ROMBIOS_GetMemory(sizes[index], "agent code scratch", 16);
            if (address != (Bitu)~((Bitu)0) && address != 0) {
                scratch = address;
                scratch_size = sizes[index];
            }
        }
        if (scratch_size == 0) {
            *error = "No free ROM BIOS space for a scratch area";
            return false;
        }
        for (uint32_t index = 0; index < scratch_size; ++index)
            phys_writeb((PhysPt)(scratch + index), 0xCC); /* INT 3 filler */
    }
    *seg = (uint16_t)(scratch >> 4);
    *off = (uint16_t)(scratch & 0xF);
    *size = scratch_size;
    return true;
}

#endif // C_DEBUG
