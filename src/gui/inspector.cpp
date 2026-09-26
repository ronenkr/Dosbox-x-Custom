/*
 *  Video inspector: current video mode + palettes, as data (VIDEO_GetInspectInfo, used by the
 *  agent) and as a separate live window (SDL2 builds), toggled from the Debug menu, the mapper
 *  event "inspector" or the -inspector command-line option.
 */
#include "dosbox.h"
#include "inspector.h"

#include "control.h"
#include "cpu.h"
#include "logging.h"
#include "mapper.h"
#include "mem.h"
#include "menu.h"
#include "regs.h"
#include "render.h"
#include "vga.h"
#include "../ints/int10.h"

#include <cstdio>
#include <cstring>

extern Render_t render;

static const char* MachineName(void)
{
    switch (machine) {
    case MCH_HERC: return "hercules";
    case MCH_CGA: return "cga";
    case MCH_TANDY: return "tandy";
    case MCH_PCJR: return "pcjr";
    case MCH_EGA: return "ega";
    case MCH_VGA: return "vga";
    case MCH_AMSTRAD: return "amstrad";
    case MCH_PC98: return "pc98";
    case MCH_MCGA: return "mcga";
    case MCH_MDA: return "mda";
    default: return "other";
    }
}

void VIDEO_GetInspectInfo(VideoInspectInfo* info)
{
    info->machine = MachineName();
    /* BIOS data area, not CurMode: save states restore the former but not the latter */
    info->bios_mode = IS_PC98_ARCH ? (CurMode != NULL ? (uint16_t)CurMode->mode : 0) : (uint16_t)(real_readb(0x40, 0x49) & 0x7F);
    info->vga_mode = vga.mode < M_MAX ? mode_texts[vga.mode] : "?";
    info->is_text = vga.mode == M_TEXT || vga.mode == M_HERC_TEXT || vga.mode == M_TANDY_TEXT;
    if (CurMode != NULL) {
        info->width = (uint32_t)CurMode->swidth;
        info->height = (uint32_t)CurMode->sheight;
        info->char_height = (uint16_t)CurMode->cheight;
    }
    if (!IS_PC98_ARCH) {
        info->text_columns = real_readw(0x40, 0x4A);
        info->text_rows = (uint16_t)(IS_EGAVGA_ARCH ? real_readb(0x40, 0x84) + 1u : 25u);
    }
    info->render_width = (uint32_t)render.src.width;
    info->render_height = (uint32_t)render.src.height;
    info->render_bpp = (uint32_t)render.src.bpp;
    info->double_width = render.src.dblw;
    info->double_height = render.src.dblh;
    info->fps = render.src.fps;
    info->dac_bits = vga.dac.bits;
    info->pel_mask = vga.dac.pel_mask;
    for (int index = 0; index < 256; ++index) {
        const RGBEntry& entry = vga.dac.rgb[index];
        info->dac_raw[index][0] = entry.red;
        info->dac_raw[index][1] = entry.green;
        info->dac_raw[index][2] = entry.blue;
        uint32_t r = entry.red, g = entry.green, b = entry.blue;
        if (vga.dac.bits != 8) { /* 6-bit DAC values */
            r = (r << 2) | (r >> 4);
            g = (g << 2) | (g >> 4);
            b = (b << 2) | (b >> 4);
        }
        info->palette[index] = ((r & 0xFF) << 16) | ((g & 0xFF) << 8) | (b & 0xFF);
    }
    for (int index = 0; index < 16; ++index) {
        info->attr_palette[index] = vga.attr.palette[index];
        info->attr_to_dac[index] = vga.dac.combine[index];
    }
    info->overscan = vga.attr.overscan_color;
    info->color_select = vga.attr.color_select;
    info->mode_control = vga.attr.mode_control;
    info->display_start = (uint32_t)vga.config.display_start;
    info->scan_len = (uint32_t)vga.config.scan_len;
    info->line_compare = (uint32_t)vga.config.line_compare;
    info->pel_panning = vga.config.pel_panning;
    info->chained = vga.config.chained;
    info->cs = SegValue(cs);
    info->ip = cpu.code.big ? reg_eip : reg_ip;
}

#if defined(C_SDL2)
#include "SDL.h"

namespace {

const int kScale = 2;          // text is the 8x8 BIOS font, doubled
const int kLine = 8 * kScale + 4;
const int kCellW = 30;
const int kCellH = 22;
const int kMargin = 10;
const int kWidth = kMargin * 2 + 16 * kCellW;
const int kHeight = kMargin * 2 + 4 * kLine + kLine + kCellW + 12 + kLine + 16 * kCellH + 8 + kLine;

SDL_Window* window = NULL;
SDL_Surface* canvas = NULL;
uint32_t window_id = 0;
uint32_t last_draw = 0;
int hover = -1;
bool auto_open_done = false;
int grid_top = 0;

uint32_t Color(uint32_t rgb)
{
    return SDL_MapRGB(canvas->format, (rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF);
}

void Fill(int x, int y, int w, int h, uint32_t rgb)
{
    SDL_Rect rect = { x, y, w, h };
    SDL_FillRect(canvas, &rect, Color(rgb));
}

void Frame(int x, int y, int w, int h, uint32_t rgb)
{
    Fill(x, y, w, 1, rgb);
    Fill(x, y + h - 1, w, 1, rgb);
    Fill(x, y, 1, h, rgb);
    Fill(x + w - 1, y, 1, h, rgb);
}

void Text(int x, int y, const char* text, uint32_t rgb, int scale = kScale)
{
    for (; *text; ++text, x += 8 * scale) {
        const uint8_t* glyph = &int10_font_08[(uint8_t)*text * 8];
        for (int row = 0; row < 8; ++row)
            for (int col = 0; col < 8; ++col)
                if (glyph[row] & (0x80 >> col))
                    Fill(x + col * scale, y + row * scale, scale, scale, rgb);
    }
}

uint32_t Contrast(uint32_t rgb)
{
    const uint32_t luma = ((rgb >> 16) & 0xFF) * 3 + ((rgb >> 8) & 0xFF) * 6 + (rgb & 0xFF);
    return luma > 1280 ? 0x000000 : 0xFFFFFF;
}

void Draw(void)
{
    VideoInspectInfo info;
    VIDEO_GetInspectInfo(&info);
    Fill(0, 0, kWidth, kHeight, 0x202020);
    char line[80];
    int y = kMargin;
    snprintf(line, sizeof(line), "Mode %02Xh %s %s", info.bios_mode, info.vga_mode.c_str(), info.machine.c_str());
    Text(kMargin, y, line, 0xFFFF55); y += kLine;
    snprintf(line, sizeof(line), "%ux%u  frame %ux%u %ubpp", info.width, info.height,
             info.render_width, info.render_height, info.render_bpp);
    Text(kMargin, y, line, 0xFFFFFF); y += kLine;
    if (info.is_text)
        snprintf(line, sizeof(line), "Text %ux%u char %u %.1fHz", info.text_columns, info.text_rows, info.char_height, info.fps);
    else
        snprintf(line, sizeof(line), "DAC %u-bit mask %02X %.1fHz", info.dac_bits, info.pel_mask, info.fps);
    Text(kMargin, y, line, 0xFFFFFF); y += kLine;
    snprintf(line, sizeof(line), "CS:IP %04X:%04X start %04X", info.cs, info.ip, info.display_start);
    Text(kMargin, y, line, 0xAAAAAA); y += kLine;

    Text(kMargin, y, "16 colours -> DAC index", 0x55FFFF); y += kLine;
    for (int index = 0; index < 16; ++index) {
        const int x = kMargin + index * kCellW;
        const uint32_t rgb = info.palette[info.attr_to_dac[index]];
        Fill(x + 1, y, kCellW - 2, kCellW - 2, rgb);
        snprintf(line, sizeof(line), "%02X", info.attr_to_dac[index]);
        Text(x + 7, y + 10, line, Contrast(rgb), 1);
        snprintf(line, sizeof(line), "%X", index);
        Text(x + 11, y + kCellW, line, 0xAAAAAA, 1);
    }
    y += kCellW + 12;

    Text(kMargin, y, "DAC palette (256)", 0x55FFFF); y += kLine;
    grid_top = y;
    bool used[256] = {};
    for (int index = 0; index < 16; ++index)
        used[info.attr_to_dac[index]] = true;
    for (int index = 0; index < 256; ++index) {
        const int x = kMargin + (index % 16) * kCellW;
        const int cy = y + (index / 16) * kCellH;
        const uint32_t rgb = info.palette[index];
        Fill(x + 1, cy + 1, kCellW - 2, kCellH - 2, rgb);
        if (used[index])
            Frame(x, cy, kCellW, kCellH, 0xFFFFFF);
        if (index == hover)
            Frame(x + 1, cy + 1, kCellW - 2, kCellH - 2, 0xFF00FF);
        snprintf(line, sizeof(line), "%02X", index);
        Text(x + 3, cy + 3, line, Contrast(rgb), 1);
    }
    y += 16 * kCellH + 8;
    if (hover >= 0 && hover < 256)
        snprintf(line, sizeof(line), "%02X #%06X (%02X %02X %02X)", hover, info.palette[hover],
                 info.dac_raw[hover][0], info.dac_raw[hover][1], info.dac_raw[hover][2]);
    else
        snprintf(line, sizeof(line), "Hover a colour for its value");
    Text(kMargin, y, line, 0xFFFFFF);

    SDL_Surface* surface = SDL_GetWindowSurface(window);
    if (surface != NULL) {
        SDL_BlitSurface(canvas, NULL, surface, NULL);
        SDL_UpdateWindowSurface(window);
    }
}

void UpdateMenu(void)
{
    if (mainMenu.item_exists("mapper_inspector")) /* get_item() aborts on unknown names */
        mainMenu.get_item("mapper_inspector").check(window != NULL).refresh_item(mainMenu);
}

void MapperToggle(bool pressed)
{
    if (pressed)
        INSPECTOR_Show(!INSPECTOR_IsShown());
}

} // namespace

void INSPECTOR_RegisterMapper(void)
{
    DOSBoxMenu::item* item = NULL;
    MAPPER_AddHandler(MapperToggle, MK_nothing, 0, "inspector", "Inspector window", &item);
    if (item != NULL) {
        item->set_text("Video/palette inspector window");
        item->set_description("Show the current video mode and palettes in a separate window");
    }
}

void INSPECTOR_Show(bool show)
{
    if (show == (window != NULL))
        return;
    if (show) {
        if (control->opt_headless)
            return; /* nothing to look at; the agent reads the same data with video.info */
        window = SDL_CreateWindow("DOSBox-X Inspector", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
                                  kWidth, kHeight, SDL_WINDOW_SHOWN);
        if (window == NULL) {
            LOG_MSG("Inspector: cannot create window: %s", SDL_GetError());
            return;
        }
        window_id = SDL_GetWindowID(window);
        canvas = SDL_CreateRGBSurfaceWithFormat(0, kWidth, kHeight, 32, SDL_PIXELFORMAT_RGB888);
        last_draw = 0;
    } else {
        if (canvas != NULL)
            SDL_FreeSurface(canvas);
        canvas = NULL;
        SDL_DestroyWindow(window);
        window = NULL;
        window_id = 0;
    }
    UpdateMenu();
}

bool INSPECTOR_IsShown(void)
{
    return window != NULL;
}

void INSPECTOR_Update(void)
{
    if (!auto_open_done) {
        auto_open_done = true;
        if (control->opt_inspector)
            INSPECTOR_Show(true);
    }
    if (window == NULL || canvas == NULL)
        return;
    const uint32_t now = SDL_GetTicks();
    if (now - last_draw < 100)
        return;
    last_draw = now;
    Draw();
}

bool INSPECTOR_HandleEvent(SDL_Event* event)
{
    if (window == NULL)
        return false;
    uint32_t id = 0;
    switch (event->type) {
    case SDL_WINDOWEVENT: id = event->window.windowID; break;
    case SDL_KEYDOWN: case SDL_KEYUP: id = event->key.windowID; break;
    case SDL_TEXTINPUT: id = event->text.windowID; break;
    case SDL_MOUSEMOTION: id = event->motion.windowID; break;
    case SDL_MOUSEBUTTONDOWN: case SDL_MOUSEBUTTONUP: id = event->button.windowID; break;
    case SDL_MOUSEWHEEL: id = event->wheel.windowID; break;
    default: return false;
    }
    if (id != window_id) {
        /* With a second window open SDL no longer turns closing the main window into SDL_QUIT */
        if (event->type == SDL_WINDOWEVENT && event->window.event == SDL_WINDOWEVENT_CLOSE) {
            SDL_Event quit;
            memset(&quit, 0, sizeof(quit));
            quit.type = SDL_QUIT;
            SDL_PushEvent(&quit);
            return true;
        }
        return false;
    }
    if (event->type == SDL_WINDOWEVENT && event->window.event == SDL_WINDOWEVENT_CLOSE) {
        INSPECTOR_Show(false);
    } else if (event->type == SDL_MOUSEMOTION) {
        const int col = (event->motion.x - kMargin) / kCellW;
        const int row = (event->motion.y - grid_top) / kCellH;
        hover = (event->motion.x >= kMargin && event->motion.y >= grid_top && col < 16 && row < 16) ? row * 16 + col : -1;
    } else if (event->type == SDL_WINDOWEVENT && event->window.event == SDL_WINDOWEVENT_EXPOSED) {
        last_draw = 0;
    }
    return true;
}

#else /* SDL1 builds: data only */

void INSPECTOR_RegisterMapper(void) {}
void INSPECTOR_Show(bool) {}
bool INSPECTOR_IsShown(void) { return false; }
void INSPECTOR_Update(void) {}
bool INSPECTOR_HandleEvent(SDL_Event*) { return false; }

#endif
