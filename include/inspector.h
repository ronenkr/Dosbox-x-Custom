/*
 *  Video inspector: a snapshot of the current video mode and palettes, and (SDL2 builds) a
 *  separate window that shows them live while a program runs.
 */
#ifndef DOSBOX_INSPECTOR_H
#define DOSBOX_INSPECTOR_H

#include <cstdint>
#include <string>

union SDL_Event;

struct VideoInspectInfo {
    std::string machine;        // cga, ega, vga, ...
    uint16_t bios_mode = 0;     // INT 10h mode number
    std::string vga_mode;       // emulator drawing mode, e.g. M_VGA, M_EGA, M_TEXT
    bool is_text = false;
    uint32_t width = 0, height = 0;       // displayed resolution
    uint16_t text_columns = 0, text_rows = 0;
    uint16_t char_height = 0;
    uint32_t render_width = 0, render_height = 0, render_bpp = 0;
    bool double_width = false, double_height = false;
    double fps = 0;
    uint8_t dac_bits = 0, pel_mask = 0;
    uint32_t palette[256] = {};          // 0xRRGGBB as displayed
    uint8_t dac_raw[256][3] = {};        // DAC register values (6 or 8 bit)
    uint8_t attr_palette[16] = {};       // attribute controller palette registers
    uint8_t attr_to_dac[16] = {};        // resulting DAC index for each of the 16 colours
    uint8_t overscan = 0, color_select = 0, mode_control = 0;
    uint32_t display_start = 0, scan_len = 0, line_compare = 0;
    uint8_t pel_panning = 0;
    bool chained = false;
    uint16_t cs = 0;
    uint32_t ip = 0;
};

void VIDEO_GetInspectInfo(VideoInspectInfo* info);

void INSPECTOR_RegisterMapper(void);    // "inspector" mapper event / menu item
void INSPECTOR_Show(bool show);
bool INSPECTOR_IsShown(void);
void INSPECTOR_Update(void);            // call often; redraws at most ~10 times a second
bool INSPECTOR_HandleEvent(SDL_Event* event); // true if the event belonged to the inspector

#endif
