#if defined(C_DEBUG) && defined(C_DOSBOX_AGENT)
#include "dosbox.h"
#include "agent/io_adapter.h"
#include "agent/agent_bridge.h"

#include "control.h"
#include "cpu.h"
#include "keyboard.h"
#include "mem.h"
#include "menu.h"
#include "mouse.h"
#include "pic.h"
#include "render.h"
#include "vga.h"
#include "../../ints/int10.h"

#if C_LIBPNG
#include <png.h>
#include <csetjmp>
#endif

#include <cctype>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <set>

extern unsigned char* scalerSourceCacheBuffer;
extern unsigned int scalerSourceCacheBufferSize;
extern Render_t render;
extern bool user_cursor_locked;
extern bool noremark_save_state;
extern bool force_load_state;
extern bool use_save_file;
extern std::string savefilename;
bool IsDebuggerActive(void);
void ReadCharAttr(uint16_t col, uint16_t row, uint8_t page, uint16_t* result);
class CEvent;
CEvent* get_mapper_event_by_name(const std::string& x);
void MAPPER_TriggerEventByName(const std::string& name);

namespace dosbox_agent {

namespace {

struct KeyName {
    const char* name;
    KBD_KEYS key;
};

// Names match the mapper's "key_<name>" events, plus a few friendly aliases.
const KeyName kKeyNames[] = {
    {"a", KBD_a}, {"b", KBD_b}, {"c", KBD_c}, {"d", KBD_d}, {"e", KBD_e}, {"f", KBD_f},
    {"g", KBD_g}, {"h", KBD_h}, {"i", KBD_i}, {"j", KBD_j}, {"k", KBD_k}, {"l", KBD_l},
    {"m", KBD_m}, {"n", KBD_n}, {"o", KBD_o}, {"p", KBD_p}, {"q", KBD_q}, {"r", KBD_r},
    {"s", KBD_s}, {"t", KBD_t}, {"u", KBD_u}, {"v", KBD_v}, {"w", KBD_w}, {"x", KBD_x},
    {"y", KBD_y}, {"z", KBD_z},
    {"0", KBD_0}, {"1", KBD_1}, {"2", KBD_2}, {"3", KBD_3}, {"4", KBD_4},
    {"5", KBD_5}, {"6", KBD_6}, {"7", KBD_7}, {"8", KBD_8}, {"9", KBD_9},
    {"f1", KBD_f1}, {"f2", KBD_f2}, {"f3", KBD_f3}, {"f4", KBD_f4}, {"f5", KBD_f5}, {"f6", KBD_f6},
    {"f7", KBD_f7}, {"f8", KBD_f8}, {"f9", KBD_f9}, {"f10", KBD_f10}, {"f11", KBD_f11}, {"f12", KBD_f12},
    {"esc", KBD_esc}, {"escape", KBD_esc},
    {"tab", KBD_tab},
    {"backspace", KBD_backspace}, {"bspace", KBD_backspace},
    {"enter", KBD_enter}, {"return", KBD_enter},
    {"space", KBD_space},
    {"lalt", KBD_leftalt}, {"alt", KBD_leftalt}, {"ralt", KBD_rightalt},
    {"lctrl", KBD_leftctrl}, {"ctrl", KBD_leftctrl}, {"rctrl", KBD_rightctrl},
    {"lshift", KBD_leftshift}, {"shift", KBD_leftshift}, {"rshift", KBD_rightshift},
    {"capslock", KBD_capslock}, {"scrolllock", KBD_scrolllock}, {"numlock", KBD_numlock},
    {"grave", KBD_grave}, {"minus", KBD_minus}, {"equals", KBD_equals}, {"backslash", KBD_backslash},
    {"lbracket", KBD_leftbracket}, {"leftbracket", KBD_leftbracket},
    {"rbracket", KBD_rightbracket}, {"rightbracket", KBD_rightbracket},
    {"semicolon", KBD_semicolon}, {"quote", KBD_quote}, {"period", KBD_period},
    {"comma", KBD_comma}, {"slash", KBD_slash}, {"lessthan", KBD_extra_lt_gt},
    {"printscreen", KBD_printscreen}, {"pause", KBD_pause},
    {"insert", KBD_insert}, {"home", KBD_home}, {"pageup", KBD_pageup}, {"pgup", KBD_pageup},
    {"delete", KBD_delete}, {"del", KBD_delete}, {"end", KBD_end},
    {"pagedown", KBD_pagedown}, {"pgdn", KBD_pagedown},
    {"left", KBD_left}, {"up", KBD_up}, {"down", KBD_down}, {"right", KBD_right},
    {"kp_0", KBD_kp0}, {"kp_1", KBD_kp1}, {"kp_2", KBD_kp2}, {"kp_3", KBD_kp3}, {"kp_4", KBD_kp4},
    {"kp_5", KBD_kp5}, {"kp_6", KBD_kp6}, {"kp_7", KBD_kp7}, {"kp_8", KBD_kp8}, {"kp_9", KBD_kp9},
    {"kp0", KBD_kp0}, {"kp1", KBD_kp1}, {"kp2", KBD_kp2}, {"kp3", KBD_kp3}, {"kp4", KBD_kp4},
    {"kp5", KBD_kp5}, {"kp6", KBD_kp6}, {"kp7", KBD_kp7}, {"kp8", KBD_kp8}, {"kp9", KBD_kp9},
    {"kp_divide", KBD_kpdivide}, {"kp_multiply", KBD_kpmultiply}, {"kp_minus", KBD_kpminus},
    {"kp_plus", KBD_kpplus}, {"kp_enter", KBD_kpenter}, {"kp_period", KBD_kpperiod},
    {"lwindows", KBD_lwindows}, {"win", KBD_lwindows}, {"rwindows", KBD_rwindows},
    {"rwinmenu", KBD_rwinmenu}, {"menu", KBD_rwinmenu},
};

std::string Lower(const std::string& value)
{
    std::string result(value);
    for (std::string::iterator it = result.begin(); it != result.end(); ++it)
        *it = static_cast<char>(std::tolower(static_cast<unsigned char>(*it)));
    return result;
}

std::string Trim(const std::string& value)
{
    const std::string::size_type first = value.find_first_not_of(" \t");
    if (first == std::string::npos)
        return std::string();
    const std::string::size_type last = value.find_last_not_of(" \t");
    return value.substr(first, last - first + 1);
}

// US layout: which key produces an ASCII character, and whether Shift is needed.
bool AsciiToKey(const char character, KBD_KEYS* key, bool* shift)
{
    *shift = false;
    if (character >= 'a' && character <= 'z') {
        int code = 0;
        AGENT_LookupKeyName(std::string(1, character), &code);
        *key = static_cast<KBD_KEYS>(code);
        return true;
    }
    if (character >= 'A' && character <= 'Z') {
        int code = 0;
        AGENT_LookupKeyName(std::string(1, static_cast<char>(character - 'A' + 'a')), &code);
        *key = static_cast<KBD_KEYS>(code);
        *shift = true;
        return true;
    }
    if (character >= '0' && character <= '9') {
        int code = 0;
        AGENT_LookupKeyName(std::string(1, character), &code);
        *key = static_cast<KBD_KEYS>(code);
        return true;
    }
    static const struct { char plain; char shifted; KBD_KEYS key; } symbols[] = {
        {'1', '!', KBD_1}, {'2', '@', KBD_2}, {'3', '#', KBD_3}, {'4', '$', KBD_4}, {'5', '%', KBD_5},
        {'6', '^', KBD_6}, {'7', '&', KBD_7}, {'8', '*', KBD_8}, {'9', '(', KBD_9}, {'0', ')', KBD_0},
        {'`', '~', KBD_grave}, {'-', '_', KBD_minus}, {'=', '+', KBD_equals},
        {'[', '{', KBD_leftbracket}, {']', '}', KBD_rightbracket}, {'\\', '|', KBD_backslash},
        {';', ':', KBD_semicolon}, {'\'', '"', KBD_quote}, {',', '<', KBD_comma},
        {'.', '>', KBD_period}, {'/', '?', KBD_slash},
    };
    for (std::size_t index = 0; index < sizeof(symbols) / sizeof(symbols[0]); ++index) {
        if (symbols[index].plain == character) {
            *key = symbols[index].key;
            return true;
        }
        if (symbols[index].shifted == character) {
            *key = symbols[index].key;
            *shift = true;
            return true;
        }
    }
    switch (character) {
    case ' ': *key = KBD_space; return true;
    case '\n': *key = KBD_enter; return true;
    case '\t': *key = KBD_tab; return true;
    case '\b': *key = KBD_backspace; return true;
    case 0x1b: *key = KBD_esc; return true;
    default: return false;
    }
}

const std::uint32_t kCp437[256] = {
    0x0020, 0x263A, 0x263B, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022, 0x25D8, 0x25CB, 0x25D9, 0x2642, 0x2640, 0x266A, 0x266B, 0x263C,
    0x25BA, 0x25C4, 0x2195, 0x203C, 0x00B6, 0x00A7, 0x25AC, 0x21A8, 0x2191, 0x2193, 0x2192, 0x2190, 0x221F, 0x2194, 0x25B2, 0x25BC,
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027, 0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047, 0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059, 0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F,
    0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x2302,
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, 0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, 0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
};

void AppendUtf8(std::string* out, const std::uint32_t code_point)
{
    if (code_point < 0x80) {
        out->push_back(static_cast<char>(code_point));
    } else if (code_point < 0x800) {
        out->push_back(static_cast<char>(0xC0 | (code_point >> 6)));
        out->push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
    } else {
        out->push_back(static_cast<char>(0xE0 | (code_point >> 12)));
        out->push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
        out->push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
    }
}

bool RequireEmulationThread(std::string* error)
{
    if (AGENT_EmulationQueue().IsBoundToCurrentThread())
        return true;
    if (error != NULL)
        *error = "Guest I/O was not dispatched on the emulation thread";
    return false;
}

// ---- Paced key playback, timed in emulated milliseconds via the PIC ----

std::deque<KeyAction> key_queue;
std::set<int> held_keys;
bool key_event_scheduled = false;

void KeyQueueEvent(Bitu /*val*/)
{
    key_event_scheduled = false;
    if (key_queue.empty())
        return;
    const KeyAction action = key_queue.front();
    key_queue.pop_front();
    KEYBOARD_AddKey(static_cast<KBD_KEYS>(action.key), action.pressed);
    if (action.pressed)
        held_keys.insert(action.key);
    else
        held_keys.erase(action.key);
    if (!key_queue.empty()) {
        key_event_scheduled = true;
        PIC_AddEvent(KeyQueueEvent, action.delay_after_ms > 0 ? static_cast<double>(action.delay_after_ms) : 0.01);
    }
}

void MouseReleaseEvent(Bitu button)
{
    Mouse_ButtonReleased(static_cast<uint8_t>(button));
}

// ---- Frame conversion and PNG encoding ----

bool FrameToRgb(std::vector<std::uint8_t>* rgb, std::uint32_t* width, std::uint32_t* height, std::string* error)
{
    if (scalerSourceCacheBuffer == NULL || render.src.width == 0 || render.src.height == 0) {
        *error = "No rendered frame is available (the render cache is inactive; use a non-complex scaler such as normal2x)";
        return false;
    }
    const Bitu bpp = render.src.bpp;
    if (bpp != 8 && bpp != 15 && bpp != 16 && bpp != 32) {
        *error = "Unsupported frame depth " + std::to_string(static_cast<unsigned long long>(bpp));
        return false;
    }
    const std::uint32_t source_width = static_cast<std::uint32_t>(render.src.width);
    const std::uint32_t source_height = static_cast<std::uint32_t>(render.src.height);
    const Bitu pitch = render.scale.cachePitch;
    if (pitch == 0 || static_cast<std::uint64_t>(pitch) * source_height > scalerSourceCacheBufferSize) {
        *error = "Render cache geometry is inconsistent";
        return false;
    }
    // Same doubling rule as CAPTURE_AddImage: only when exactly one axis is doubled.
    const bool double_width = render.src.dblw != render.src.dblh && render.src.dblw;
    const bool double_height = render.src.dblw != render.src.dblh && render.src.dblh;
    *width = source_width * (double_width ? 2u : 1u);
    *height = source_height * (double_height ? 2u : 1u);
    rgb->assign(static_cast<std::size_t>(*width) * (*height) * 3u, 0);

    for (std::uint32_t y = 0; y < *height; ++y) {
        const std::uint8_t* line = scalerSourceCacheBuffer + (double_height ? y / 2u : y) * pitch;
        std::uint8_t* out = &(*rgb)[static_cast<std::size_t>(y) * (*width) * 3u];
        for (std::uint32_t x = 0; x < *width; ++x) {
            const std::uint32_t sx = double_width ? x / 2u : x;
            std::uint8_t r = 0, g = 0, b = 0;
            if (bpp == 8) {
                const std::uint8_t index = line[sx];
                r = render.pal.rgb[index].red;
                g = render.pal.rgb[index].green;
                b = render.pal.rgb[index].blue;
            } else if (bpp == 15) {
                const std::uint16_t pixel = reinterpret_cast<const std::uint16_t*>(line)[sx];
                b = static_cast<std::uint8_t>(((pixel & 0x001f) * 0x21) >> 2);
                g = static_cast<std::uint8_t>(((pixel & 0x03e0) * 0x21) >> 7);
                r = static_cast<std::uint8_t>(((pixel & 0x7c00) * 0x21) >> 12);
            } else if (bpp == 16) {
                const std::uint16_t pixel = reinterpret_cast<const std::uint16_t*>(line)[sx];
                b = static_cast<std::uint8_t>(((pixel & 0x001f) * 0x21) >> 2);
                g = static_cast<std::uint8_t>(((pixel & 0x07e0) * 0x41) >> 9);
                r = static_cast<std::uint8_t>(((pixel & 0xf800) * 0x21) >> 13);
            } else {
                b = line[sx * 4 + 0];
                g = line[sx * 4 + 1];
                r = line[sx * 4 + 2];
            }
            out[x * 3 + 0] = r;
            out[x * 3 + 1] = g;
            out[x * 3 + 2] = b;
        }
    }
    return true;
}

#if C_LIBPNG
void PngWrite(png_structp png, png_bytep data, png_size_t length)
{
    std::vector<std::uint8_t>* out = static_cast<std::vector<std::uint8_t>*>(png_get_io_ptr(png));
    out->insert(out->end(), data, data + length);
}

void PngFlush(png_structp)
{}

bool EncodePng(const std::vector<std::uint8_t>& rgb,
               const std::uint32_t width,
               const std::uint32_t height,
               std::vector<std::uint8_t>* out,
               std::string* error)
{
    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (png == NULL) {
        *error = "png_create_write_struct failed";
        return false;
    }
    png_infop info = png_create_info_struct(png);
    if (info == NULL) {
        png_destroy_write_struct(&png, NULL);
        *error = "png_create_info_struct failed";
        return false;
    }
    std::vector<png_bytep> rows(height);
    for (std::uint32_t y = 0; y < height; ++y)
        rows[y] = const_cast<png_bytep>(&rgb[static_cast<std::size_t>(y) * width * 3u]);
    out->clear();
    if (setjmp(png_jmpbuf(png))) {
        png_destroy_write_struct(&png, &info);
        *error = "libpng failed while encoding the screenshot";
        return false;
    }
    png_set_write_fn(png, out, PngWrite, PngFlush);
    png_set_compression_level(png, 6);
    png_set_IHDR(png, info, width, height, 8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png, info);
    png_write_image(png, &rows[0]);
    png_write_end(png, NULL);
    png_destroy_write_struct(&png, &info);
    return true;
}
#endif

bool FileExists(const std::string& path)
{
    std::ifstream file(path.c_str(), std::ios::binary);
    return file.good();
}

bool ValidSlot(const std::uint32_t slot, std::string* error)
{
    if (slot < SaveState::SLOT_COUNT * SaveState::MAX_PAGE)
        return true;
    *error = "Save-state slot must be below " + std::to_string(SaveState::SLOT_COUNT * SaveState::MAX_PAGE);
    return false;
}

// Save/load must never prompt (remark box, load confirmation) and may target an explicit
// file; both are controlled by globals, restored when the guard goes out of scope.
class SaveGlobalsGuard {
public:
    explicit SaveGlobalsGuard(const std::string& path)
        : noremark(noremark_save_state), force(force_load_state),
          use_file(use_save_file), file_name(savefilename)
    {
        noremark_save_state = true;
        force_load_state = true;
        if (!path.empty()) {
            use_save_file = true;
            savefilename = path;
        }
    }
    ~SaveGlobalsGuard()
    {
        noremark_save_state = noremark;
        force_load_state = force;
        use_save_file = use_file;
        savefilename = file_name;
    }

private:
    bool noremark;
    bool force;
    bool use_file;
    std::string file_name;
};

// Save states restore guest memory and VGA registers but not the INT 10h CurMode pointer, so the
// mode comes from the BIOS data area and the VGA drawing mode, which are always current.
std::uint16_t CurrentVideoMode()
{
    if (IS_PC98_ARCH)
        return CurMode != NULL ? static_cast<std::uint16_t>(CurMode->mode) : 0;
    return static_cast<std::uint16_t>(real_readb(BIOSMEM_SEG, BIOSMEM_CURRENT_MODE) & 0x7Fu);
}

bool CurrentModeIsText()
{
    return vga.mode == M_TEXT || vga.mode == M_HERC_TEXT || vga.mode == M_TANDY_TEXT;
}

class ProductionIoBackend final : public IoBackend {
public:
    bool QueueKeys(const std::vector<KeyAction>& actions, std::size_t* pending, std::string* error) override
    {
        if (!RequireEmulationThread(error))
            return false;
        for (std::vector<KeyAction>::const_iterator it = actions.begin(); it != actions.end(); ++it)
            key_queue.push_back(*it);
        if (!key_event_scheduled && !key_queue.empty()) {
            key_event_scheduled = true;
            PIC_AddEvent(KeyQueueEvent, 0.01);
        }
        if (pending != NULL)
            *pending = key_queue.size();
        return true;
    }

    bool ClearKeys(std::string* error) override
    {
        if (!RequireEmulationThread(error))
            return false;
        PIC_RemoveEvents(KeyQueueEvent);
        key_event_scheduled = false;
        key_queue.clear();
        // Never leave a modifier stuck down in the guest.
        for (std::set<int>::const_iterator it = held_keys.begin(); it != held_keys.end(); ++it)
            KEYBOARD_AddKey(static_cast<KBD_KEYS>(*it), false);
        held_keys.clear();
        return true;
    }

    std::size_t PendingKeys() const override
    {
        return key_queue.size();
    }

    bool Mouse(const MouseCommand& command, std::string* error) override
    {
        if (!RequireEmulationThread(error))
            return false;
        if (IsDebuggerActive()) {
            *error = "The debugger has the CPU stopped; resume execution before sending mouse input";
            return false;
        }
        if (command.has_absolute) {
            const float x = command.x < 0.0f ? 0.0f : (command.x > 1.0f ? 1.0f : command.x);
            const float y = command.y < 0.0f ? 0.0f : (command.y > 1.0f ? 1.0f : command.y);
            Mouse_CursorMoved(0.0f, 0.0f, x, y, false);
        }
        if (command.has_relative) {
            // Relative motion only reaches mickey counters while the cursor counts as captured.
            const bool was_locked = user_cursor_locked;
            user_cursor_locked = true;
            Mouse_CursorMoved(command.dx, command.dy, 0.0f, 0.0f, true);
            user_cursor_locked = was_locked;
        }
        if (command.button >= 0) {
            const uint8_t button = static_cast<uint8_t>(command.button);
            switch (command.action) {
            case MouseButtonAction::Press: Mouse_ButtonPressed(button); break;
            case MouseButtonAction::Release: Mouse_ButtonReleased(button); break;
            case MouseButtonAction::Click:
                Mouse_ButtonPressed(button);
                PIC_AddEvent(MouseReleaseEvent, 60.0, button);
                break;
            case MouseButtonAction::None: break;
            }
        }
        if (command.wheel != 0)
            Mouse_WheelMoved(command.wheel);
        return true;
    }

    bool CaptureScreen(ScreenImage* image, std::string* error) override
    {
        if (!RequireEmulationThread(error))
            return false;
#if C_LIBPNG
        std::vector<std::uint8_t> rgb;
        if (!FrameToRgb(&rgb, &image->width, &image->height, error))
            return false;
        image->video_mode = CurrentVideoMode();
        return EncodePng(rgb, image->width, image->height, &image->png, error);
#else
        (void)image;
        *error = "This build has no libpng support";
        return false;
#endif
    }

    bool ReadScreenText(const bool attributes, const bool force_graphics, ScreenText* text, std::string* error) override
    {
        if (!RequireEmulationThread(error))
            return false;
        if (IS_PC98_ARCH) {
            *error = "Screen text is not supported for PC-98 machines";
            return false;
        }
        if (CurMode == NULL) {
            *error = "Video BIOS is not initialized yet";
            return false;
        }
        text->video_mode = CurrentVideoMode();
        text->is_text = CurrentModeIsText();
        text->page = real_readb(BIOSMEM_SEG, BIOSMEM_CURRENT_PAGE);
        text->columns = real_readw(BIOSMEM_SEG, BIOSMEM_NB_COLS);
        text->rows = static_cast<std::uint16_t>(IS_EGAVGA_ARCH ? real_readb(BIOSMEM_SEG, BIOSMEM_NB_ROWS) + 1u : 25u);
        text->cursor_column = CURSOR_POS_COL(text->page);
        text->cursor_row = CURSOR_POS_ROW(text->page);
        text->lines.clear();
        text->attributes.clear();
        if (!text->is_text && !force_graphics)
            return true;
        if (text->columns == 0 || text->columns > 256 || text->rows == 0 || text->rows > 128) {
            *error = "BIOS reports an implausible text geometry";
            return false;
        }
        static const char hex[] = "0123456789ABCDEF";
        for (std::uint16_t row = 0; row < text->rows; ++row) {
            std::string line;
            std::string attribute_line;
            for (std::uint16_t column = 0; column < text->columns; ++column) {
                uint16_t cell = 0;
                ReadCharAttr(column, row, text->page, &cell);
                AppendUtf8(&line, kCp437[cell & 0xffu]);
                if (attributes) {
                    const std::uint8_t attribute = static_cast<std::uint8_t>(cell >> 8);
                    attribute_line.push_back(hex[attribute >> 4]);
                    attribute_line.push_back(hex[attribute & 0x0f]);
                }
            }
            text->lines.push_back(line);
            if (attributes)
                text->attributes.push_back(attribute_line);
        }
        return true;
    }

    bool GetStatus(MachineStatus* status, std::string* error) override
    {
        if (!RequireEmulationThread(error))
            return false;
        status->debugger_active = IsDebuggerActive();
        status->emulated_ms = static_cast<std::uint64_t>(PIC_FullIndex());
        status->cycles = static_cast<std::int64_t>(CPU_CycleMax);
        status->cycles_auto = CPU_CycleAutoAdjust;
        status->video_mode = CurrentVideoMode();
        status->is_text = CurrentModeIsText();
        status->pending_input = key_queue.size();
        status->frame_width = render.src.width;
        status->frame_height = render.src.height;
        return true;
    }

    bool SetSpeed(const std::string& cycles, const int turbo, std::string* error) override
    {
        if (!RequireEmulationThread(error))
            return false;
        if (!cycles.empty())
            SetVal("cpu", "cycles", cycles);
        if (turbo >= 0)
            SetVal("cpu", "turbo", turbo ? "true" : "false");
        return true;
    }

    bool SaveStateSlot(const std::uint32_t slot, const std::string& path, std::string* error) override
    {
        if (!RequireEmulationThread(error) || !ValidSlot(slot, error))
            return false;
        SaveGlobalsGuard guard(path);
        if (!path.empty())
            std::remove(path.c_str()); // so a failed save cannot look like success
        try {
            SaveState::instance().save(path.empty() ? slot : 0);
        } catch (...) {
            *error = "Saving state failed";
            return false;
        }
        if (path.empty() ? SaveState::instance().isEmpty(slot) : !FileExists(path)) {
            *error = "Saving state failed (see the DOSBox-X log)";
            return false;
        }
        return true;
    }

    bool LoadStateSlot(const std::uint32_t slot, const std::string& path, std::string* error) override
    {
        if (!RequireEmulationThread(error) || !ValidSlot(slot, error))
            return false;
        if (path.empty() ? SaveState::instance().isEmpty(slot) : !FileExists(path)) {
            *error = path.empty() ? "Save-state slot " + std::to_string(slot) + " is empty"
                                  : "Save-state file does not exist: " + path;
            return false;
        }
        SaveGlobalsGuard guard(path);
        try {
            SaveState::instance().load(path.empty() ? slot : 0);
        } catch (...) {
            *error = "Loading state failed";
            return false;
        }
        return true;
    }

    bool CaptureRaw(RawFrame* frame, std::string* error) override
    {
        if (!RequireEmulationThread(error))
            return false;
        if (scalerSourceCacheBuffer == NULL || render.src.width == 0 || render.src.height == 0) {
            *error = "No rendered frame is available";
            return false;
        }
        const Bitu bpp = render.src.bpp;
        const std::size_t bytes_per_pixel = bpp == 8 ? 1u : (bpp == 15 || bpp == 16) ? 2u : bpp == 32 ? 4u : 0u;
        const Bitu pitch = render.scale.cachePitch;
        if (bytes_per_pixel == 0 || pitch == 0 ||
            static_cast<std::uint64_t>(pitch) * render.src.height > scalerSourceCacheBufferSize) {
            *error = "Unsupported or inconsistent frame layout";
            return false;
        }
        frame->width = static_cast<std::uint32_t>(render.src.width);
        frame->height = static_cast<std::uint32_t>(render.src.height);
        frame->bpp = static_cast<std::uint32_t>(bpp);
        frame->double_width = render.src.dblw;
        frame->double_height = render.src.dblh;
        frame->video_mode = CurrentVideoMode();
        const std::size_t row_bytes = frame->width * bytes_per_pixel;
        frame->pixels.resize(row_bytes * frame->height);
        for (std::uint32_t y = 0; y < frame->height; ++y)
            std::memcpy(&frame->pixels[y * row_bytes], scalerSourceCacheBuffer + y * pitch, row_bytes);
        frame->palette.clear();
        frame->indices.clear();
        frame->unmatched_pixels = 0;
        if (bpp == 8) {
            for (int index = 0; index < 256; ++index) {
                frame->palette.push_back((static_cast<std::uint32_t>(render.pal.rgb[index].red) << 16) |
                                         (static_cast<std::uint32_t>(render.pal.rgb[index].green) << 8) |
                                         render.pal.rgb[index].blue);
            }
        } else if (bpp == 32 && IS_VGA_ARCH && vga.mode != M_LIN15 &&
                   vga.mode != M_LIN16 && vga.mode != M_LIN24 && vga.mode != M_LIN32) {
            // Palettised mode rendered through the DAC: invert xlat32 to get indices back.
            std::map<std::uint32_t, std::uint8_t> reverse;
            for (int index = 255; index >= 0; --index) {
                const std::uint32_t color = vga.dac.xlat32[index] & 0x00FFFFFFu;
                reverse[color] = static_cast<std::uint8_t>(index); // lowest index wins
                const std::uint8_t* bytes = reinterpret_cast<const std::uint8_t*>(&vga.dac.xlat32[index]);
                frame->palette.insert(frame->palette.begin(),
                                      (static_cast<std::uint32_t>(bytes[2]) << 16) |
                                      (static_cast<std::uint32_t>(bytes[1]) << 8) | bytes[0]);
            }
            frame->indices.resize(static_cast<std::size_t>(frame->width) * frame->height);
            const std::uint32_t* source = reinterpret_cast<const std::uint32_t*>(&frame->pixels[0]);
            for (std::size_t pixel = 0; pixel < frame->indices.size(); ++pixel) {
                const std::map<std::uint32_t, std::uint8_t>::const_iterator found =
                    reverse.find(source[pixel] & 0x00FFFFFFu);
                if (found == reverse.end()) {
                    ++frame->unmatched_pixels; // overlays, or a palette change mid-frame
                    frame->indices[pixel] = 0;
                } else {
                    frame->indices[pixel] = found->second;
                }
            }
        }
        return true;
    }

    bool TriggerMapperEvent(const std::string& name, std::string* error) override
    {
        if (!RequireEmulationThread(error))
            return false;
        if (get_mapper_event_by_name(name) == NULL) {
            *error = "Unknown mapper event: " + name;
            return false;
        }
        MAPPER_TriggerEventByName(name);
        return true;
    }
};

// Deterministic stand-in for the protocol self-test and unit tests.
class FakeIoBackend final : public IoBackend {
public:
    bool QueueKeys(const std::vector<KeyAction>& actions, std::size_t* pending, std::string*) override
    {
        queued += actions.size();
        if (pending != NULL)
            *pending = 0;
        return true;
    }
    bool ClearKeys(std::string*) override { return true; }
    std::size_t PendingKeys() const override { return 0; }
    bool Mouse(const MouseCommand&, std::string*) override { return true; }
    bool CaptureScreen(ScreenImage* image, std::string*) override
    {
        // 1x1 black RGB PNG
        static const std::uint8_t png[] = {
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
            0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0x60, 0x60, 0x60, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x01, 0x27, 0x34, 0x27, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
            0x44, 0xAE, 0x42, 0x60, 0x82};
        image->width = 1;
        image->height = 1;
        image->video_mode = 3;
        image->png.assign(png, png + sizeof(png));
        return true;
    }
    bool ReadScreenText(const bool attributes, bool, ScreenText* text, std::string*) override
    {
        text->is_text = true;
        text->video_mode = 3;
        text->columns = 80;
        text->rows = 25;
        text->cursor_column = 4;
        text->cursor_row = 0;
        text->lines.assign(25, std::string(80, ' '));
        text->lines[0].replace(0, 4, "C:\\>");
        if (attributes)
            text->attributes.assign(25, std::string(160, '0'));
        return true;
    }
    bool GetStatus(MachineStatus* status, std::string*) override
    {
        status->video_mode = 3;
        status->is_text = true;
        status->cycles = 3000;
        return true;
    }
    bool SetSpeed(const std::string&, int, std::string*) override { return true; }
    bool CaptureRaw(RawFrame* frame, std::string*) override
    {
        frame->width = 2;
        frame->height = 1;
        frame->bpp = 8;
        frame->video_mode = 0x13;
        frame->pixels.assign(2, 0);
        frame->pixels[1] = 1;
        frame->palette.assign(256, 0);
        frame->palette[1] = 0xFFFFFF;
        return true;
    }
    bool SaveStateSlot(std::uint32_t, const std::string&, std::string*) override { return true; }
    bool LoadStateSlot(std::uint32_t, const std::string&, std::string*) override { return true; }
    bool TriggerMapperEvent(const std::string& name, std::string* error) override
    {
        if (name.compare(0, 5, "hand_") == 0)
            return true;
        *error = "Unknown mapper event: " + name;
        return false;
    }

private:
    std::size_t queued = 0;
};

} // namespace

std::unique_ptr<IoBackend> AGENT_CreateProductionIoBackend()
{
    return std::unique_ptr<IoBackend>(new ProductionIoBackend());
}

std::unique_ptr<IoBackend> AGENT_CreateFakeIoBackend()
{
    return std::unique_ptr<IoBackend>(new FakeIoBackend());
}

bool AGENT_LookupKeyName(const std::string& name, int* key)
{
    const std::string normalized = Lower(Trim(name));
    for (std::size_t index = 0; index < sizeof(kKeyNames) / sizeof(kKeyNames[0]); ++index) {
        if (normalized == kKeyNames[index].name) {
            *key = static_cast<int>(kKeyNames[index].key);
            return true;
        }
    }
    return false;
}

bool AGENT_ExpandKeyCombo(const std::string& combo,
                          const std::uint32_t hold_ms,
                          const std::uint32_t pace_ms,
                          std::vector<KeyAction>* actions,
                          std::string* error)
{
    std::vector<int> keys;
    std::string::size_type start = 0;
    const std::string trimmed = Trim(combo);
    if (trimmed.empty()) {
        *error = "Empty key combination";
        return false;
    }
    // Parts are separated by "+"; the plus key itself is "equals" with shift, or "kp_plus".
    while (start <= trimmed.size()) {
        std::string::size_type plus = trimmed.find('+', start);
        if (plus == std::string::npos)
            plus = trimmed.size();
        const std::string part = trimmed.substr(start, plus - start);
        int key = 0;
        if (!AGENT_LookupKeyName(part, &key)) {
            *error = "Unknown key name '" + part + "' in '" + combo + "'";
            return false;
        }
        keys.push_back(key);
        start = plus + 1;
    }
    for (std::size_t index = 0; index < keys.size(); ++index) {
        KeyAction down;
        down.key = keys[index];
        down.pressed = true;
        down.delay_after_ms = index + 1 == keys.size() ? hold_ms : pace_ms;
        actions->push_back(down);
    }
    for (std::size_t index = keys.size(); index-- > 0;) {
        KeyAction up;
        up.key = keys[index];
        up.pressed = false;
        up.delay_after_ms = pace_ms;
        actions->push_back(up);
    }
    return true;
}

bool AGENT_ExpandText(const std::string& utf8_text,
                      const std::uint32_t pace_ms,
                      std::vector<KeyAction>* actions,
                      std::string* error)
{
    int shift_key = 0;
    AGENT_LookupKeyName("lshift", &shift_key);
    for (std::size_t index = 0; index < utf8_text.size(); ++index) {
        char character = utf8_text[index];
        if (static_cast<unsigned char>(character) >= 0x80) {
            *error = "Character at byte " + std::to_string(index) +
                     " has no US-keyboard equivalent; use input.keys for special keys";
            return false;
        }
        if (character == '\r') {
            if (index + 1 < utf8_text.size() && utf8_text[index + 1] == '\n')
                continue; // CRLF counts as one Enter
            character = '\n';
        }
        KBD_KEYS key = KBD_NONE;
        bool shift = false;
        if (!AsciiToKey(character, &key, &shift)) {
            *error = "Character code " + std::to_string(static_cast<int>(character)) + " cannot be typed";
            return false;
        }
        if (shift) {
            KeyAction shift_down;
            shift_down.key = shift_key;
            shift_down.pressed = true;
            shift_down.delay_after_ms = pace_ms / 2u;
            actions->push_back(shift_down);
        }
        KeyAction down;
        down.key = static_cast<int>(key);
        down.pressed = true;
        down.delay_after_ms = pace_ms / 2u;
        actions->push_back(down);
        KeyAction up;
        up.key = static_cast<int>(key);
        up.pressed = false;
        up.delay_after_ms = shift ? pace_ms / 2u : pace_ms;
        actions->push_back(up);
        if (shift) {
            KeyAction shift_up;
            shift_up.key = shift_key;
            shift_up.pressed = false;
            shift_up.delay_after_ms = pace_ms;
            actions->push_back(shift_up);
        }
    }
    return true;
}

std::string AGENT_Cp437ToUtf8(const std::uint8_t value)
{
    std::string out;
    AppendUtf8(&out, kCp437[value]);
    return out;
}

} // namespace dosbox_agent
#endif // defined(C_DEBUG) && defined(C_DOSBOX_AGENT)
