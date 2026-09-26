#ifndef DOSBOX_AGENT_IO_ADAPTER_H
#define DOSBOX_AGENT_IO_ADAPTER_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace dosbox_agent {

// One scheduled keyboard transition. Key codes are the emulator's KBD_KEYS values,
// resolved from names by AGENT_LookupKeyName() so the protocol layer never needs
// the emulator headers.
struct KeyAction {
    int key = 0;
    bool pressed = false;
    std::uint32_t delay_after_ms = 0; // emulated milliseconds to wait before the next action
};

struct ScreenText {
    bool is_text = false;
    std::uint16_t video_mode = 0;
    std::uint16_t columns = 0;
    std::uint16_t rows = 0;
    std::uint16_t cursor_column = 0;
    std::uint16_t cursor_row = 0;
    std::uint8_t page = 0;
    std::vector<std::string> lines;      // UTF-8, trailing blanks kept so columns line up
    std::vector<std::string> attributes; // one hex byte pair per cell, only when requested
};

struct ScreenImage {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint16_t video_mode = 0;
    std::vector<std::uint8_t> png;
};

// The emulator's source frame before scaling: palette indices for 8 bpp modes,
// packed little-endian pixels otherwise. Doubling flags say how to get the aspect right.
struct RawFrame {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint32_t bpp = 0;
    bool double_width = false;
    bool double_height = false;
    std::uint16_t video_mode = 0;
    std::vector<std::uint8_t> pixels;   // rows packed without padding
    std::vector<std::uint32_t> palette; // 0xRRGGBB, 256 entries when bpp == 8 or indices are present
    // VGA renders palettised modes (CGA/EGA/VGA 256) at 32 bpp; indices recovers the DAC index
    // of every pixel by inverting the DAC colour table (lowest index wins for duplicate colours).
    std::vector<std::uint8_t> indices;
    std::uint32_t unmatched_pixels = 0;
};

struct MachineStatus {
    bool debugger_active = false;
    std::uint64_t emulated_ms = 0;
    std::int64_t cycles = 0;
    bool cycles_auto = false;
    std::uint16_t video_mode = 0;
    bool is_text = false;
    std::size_t pending_input = 0;
    std::uint64_t frame_width = 0;
    std::uint64_t frame_height = 0;
};

enum class MouseButtonAction {
    None,
    Press,
    Release,
    Click
};

struct MouseCommand {
    bool has_absolute = false;
    float x = 0.0f; // 0..1 of the guest screen
    float y = 0.0f;
    bool has_relative = false;
    float dx = 0.0f; // host pixels
    float dy = 0.0f;
    int button = -1; // 0 left, 1 right, 2 middle
    MouseButtonAction action = MouseButtonAction::None;
    std::int32_t wheel = 0;
};

// Guest I/O that does not require a debugger session: keyboard, mouse, screen,
// save states and mapper events. Every method except the name lookups must run
// on the emulation thread.
class IoBackend {
public:
    virtual ~IoBackend() {}
    virtual bool QueueKeys(const std::vector<KeyAction>& actions, std::size_t* pending, std::string* error) = 0;
    virtual bool ClearKeys(std::string* error) = 0;
    virtual std::size_t PendingKeys() const = 0;
    virtual bool Mouse(const MouseCommand& command, std::string* error) = 0;
    virtual bool CaptureScreen(ScreenImage* image, std::string* error) = 0;
    virtual bool CaptureRaw(RawFrame* frame, std::string* error) = 0;
    virtual bool ReadScreenText(bool attributes, bool force_graphics, ScreenText* text, std::string* error) = 0;
    virtual bool GetStatus(MachineStatus* status, std::string* error) = 0;
    virtual bool SetSpeed(const std::string& cycles, int turbo /* -1 keep, 0 off, 1 on */, std::string* error) = 0;
    // A non-empty path saves to / loads from that file instead of the numbered slot.
    virtual bool SaveStateSlot(std::uint32_t slot, const std::string& path, std::string* error) = 0;
    virtual bool LoadStateSlot(std::uint32_t slot, const std::string& path, std::string* error) = 0;
    virtual bool TriggerMapperEvent(const std::string& name, std::string* error) = 0;
};

std::unique_ptr<IoBackend> AGENT_CreateProductionIoBackend();
std::unique_ptr<IoBackend> AGENT_CreateFakeIoBackend();

// Key names follow the mapper's "key_<name>" names without the prefix
// (e.g. "a", "enter", "esc", "f1", "lshift", "left", "kp5").
bool AGENT_LookupKeyName(const std::string& name, int* key);

// Expands "ctrl+alt+del" / "shift+f10" / "enter" into press/release actions.
bool AGENT_ExpandKeyCombo(const std::string& combo,
                          std::uint32_t hold_ms,
                          std::uint32_t pace_ms,
                          std::vector<KeyAction>* actions,
                          std::string* error);

// Translates text (US layout; \n and \r become Enter, \t Tab, \b Backspace)
// into key actions. Characters without a US-keyboard equivalent are rejected.
bool AGENT_ExpandText(const std::string& utf8_text,
                      std::uint32_t pace_ms,
                      std::vector<KeyAction>* actions,
                      std::string* error);

// CP437 byte to UTF-8, used for screen text.
std::string AGENT_Cp437ToUtf8(std::uint8_t value);

} // namespace dosbox_agent

#endif
