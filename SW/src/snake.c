/*******************************************************************************
 * Project:     SeedMate
 * File:        snake.c
 *
 * Summary:
 *   Snake game shown as a decoy at power-on (see snake.h).
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <string.h>
#include "definitions.h"
#include "SPI.h"
#include "TFT.h"
#include "fountain.h"
#include "snake.h"

// Buttons, active low (same pins as main.c)
#define KEY_BACK    PORTBbits.RB2
#define KEY_LEFT    PORTCbits.RC0
#define KEY_OK      PORTCbits.RC1
#define KEY_DOWN    PORTBbits.RB3
#define KEY_UP      PORTCbits.RC2
#define KEY_RIGHT   PORTAbits.RA4

// Board: 20 x 14 cells of 8 px under a 16 px score line
#define CELL        8
#define COLS        20
#define ROWS        14
#define TOP         16
#define CELLS       (COLS * ROWS)

#define TICKS_PER_MS    (CPU_CLOCK_FREQUENCY / 2000u)   // Core timer runs at SYSCLK / 2
#define STEP_START_MS   220     // Time per move at the start...
#define STEP_MIN_MS     80      // ...getting faster down to this
#define STEP_FASTER_MS  6       // Faster by this per food eaten

#define COLOR_BG        0x0000
#define COLOR_SNAKE     0x07E0
#define COLOR_HEAD      0xAFE5
#define COLOR_FOOD      0xF800
#define COLOR_TEXT      0xFFFF
#define COLOR_LINE      0x8410

enum { DIR_UP, DIR_DOWN, DIR_LEFT, DIR_RIGHT };

// Board state, in the fountain part buffer: a ring of body cells (head at
// 'head', tail at 'tail') and one occupancy bit per cell
static uint16_t *body;          // CELLS cell indexes
static uint8_t *occupied;       // CELLS / 8 + 1 bytes
static uint16_t head, tail, length;
static uint16_t food;
static uint16_t score, best;
static uint32_t rng_state;

// Game randomness only (food position): xorshift32 seeded from the core
// timer at the first key press. Never used for anything secret.
static uint32_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static bool cell_used(uint16_t c) {
    return (occupied[c >> 3] >> (c & 7)) & 1u;
}

static void cell_set(uint16_t c, bool used) {
    if (used) occupied[c >> 3] |= (uint8_t)(1u << (c & 7));
    else      occupied[c >> 3] &= (uint8_t)~(1u << (c & 7));
}

static void draw_cell(uint16_t c, uint16_t color) {
    unsigned char x = (unsigned char)((c % COLS) * CELL);
    unsigned char y = (unsigned char)(TOP + (c / COLS) * CELL);
    rectan(x, y, (unsigned char)(x + CELL - 2), (unsigned char)(y + CELL - 2), color);
}

static void number_text(char *out, const char *label, uint16_t value) {
    char digits[6];
    int n = 0;
    do {
        digits[n++] = (char)('0' + value % 10);
        value /= 10;
    } while (value > 0);
    strcpy(out, label);
    out += strlen(out);
    while (n > 0) *out++ = digits[--n];
    *out = '\0';
}

static void draw_score(void) {
    char text[16];
    number_text(text, "SCORE ", score);     // Only grows during a game
    drawtext(2, 4, text, COLOR_TEXT, COLOR_BG, 1);
    number_text(text, "BEST ", best);
    drawtext(100, 4, text, COLOR_TEXT, COLOR_BG, 1);
}

static void place_food(void) {
    if (length >= CELLS) return;
    uint16_t c = (uint16_t)(rng_next() % CELLS);
    while (cell_used(c)) c = (uint16_t)((c + 1) % CELLS);
    food = c;
    draw_cell(food, COLOR_FOOD);
}

// Waits for all keys up, then for OK
static void wait_ok(void) {
    while (KEY_OK == 0) SYS_Tasks();
    delay_ms(30);
    while (KEY_OK != 0) {
        SYS_Tasks();
        rng_state += 1;                 // Time to the press varies the food
    }
    delay_ms(30);
    while (KEY_OK == 0) SYS_Tasks();
    if (rng_state == 0) rng_state = 0x2545F491u;
}

static void title_screen(void) {
    rectan(0, 0, 159, 127, COLOR_BG);
    drawtext(35, 30, "SNAKE", COLOR_SNAKE, COLOR_BG, 3);
    drawtext(26, 75, "ARROWS: MOVE", COLOR_TEXT, COLOR_BG, 1);
    drawtext(26, 87, "OK: PAUSE", COLOR_TEXT, COLOR_BG, 1);
    drawtext(26, 110, "PRESS OK TO PLAY", COLOR_TEXT, COLOR_BG, 1);
    wait_ok();
}

static void new_game(void) {
    memset(occupied, 0, CELLS / 8 + 1);
    rectan(0, 0, 159, 127, COLOR_BG);
    drawFastHLine(0, TOP - 3, 160, COLOR_LINE);
    score = 0;
    length = 3;
    tail = 0;
    head = 2;
    uint16_t start = (uint16_t)((ROWS / 2) * COLS + COLS / 2 - 2);
    for (uint16_t i = 0; i < length; i++) {
        body[i] = (uint16_t)(start + i);
        cell_set(body[i], true);
        draw_cell(body[i], (i == length - 1) ? COLOR_HEAD : COLOR_SNAKE);
    }
    draw_score();
    place_food();
}

// Plays one game; returns when the snake hits a wall or itself
static void play(void) {
    uint8_t dir = DIR_RIGHT, next_dir = DIR_RIGHT;
    uint32_t step_ms = STEP_START_MS;
    uint32_t last_step = _CP0_GET_COUNT();
    bool ok_was_down = false;

    while (true) {
        SYS_Tasks();

        // Turns (never straight back into the body)
        if (KEY_UP == 0 && dir != DIR_DOWN) next_dir = DIR_UP;
        else if (KEY_DOWN == 0 && dir != DIR_UP) next_dir = DIR_DOWN;
        else if (KEY_LEFT == 0 && dir != DIR_RIGHT) next_dir = DIR_LEFT;
        else if (KEY_RIGHT == 0 && dir != DIR_LEFT) next_dir = DIR_RIGHT;

        // OK pauses
        bool ok_down = (KEY_OK == 0);
        if (ok_down && !ok_was_down) {
            drawtext(62, 4, "PAUSE", COLOR_TEXT, COLOR_BG, 1);
            wait_ok();
            drawtext(62, 4, "     ", COLOR_TEXT, COLOR_BG, 1);
            last_step = _CP0_GET_COUNT();
            ok_down = false;
        }
        ok_was_down = ok_down;

        if ((uint32_t)(_CP0_GET_COUNT() - last_step) < step_ms * TICKS_PER_MS) continue;
        last_step = _CP0_GET_COUNT();
        dir = next_dir;

        uint16_t h = body[head];
        int x = h % COLS, y = h / COLS;
        if (dir == DIR_UP) y--;
        else if (dir == DIR_DOWN) y++;
        else if (dir == DIR_LEFT) x--;
        else x++;
        if (x < 0 || x >= COLS || y < 0 || y >= ROWS) return;      // Wall
        uint16_t n = (uint16_t)(y * COLS + x);

        bool eats = (n == food);
        if (!eats) {
            // The tail moves away first, so following it is allowed
            cell_set(body[tail], false);
            draw_cell(body[tail], COLOR_BG);
            tail = (uint16_t)((tail + 1) % CELLS);
            length--;
        }
        if (cell_used(n)) return;                                   // Itself

        draw_cell(body[head], COLOR_SNAKE);
        head = (uint16_t)((head + 1) % CELLS);
        body[head] = n;
        cell_set(n, true);
        length++;
        draw_cell(n, COLOR_HEAD);

        if (eats) {
            score++;
            if (score > best) best = score;
            draw_score();
            if (step_ms > STEP_MIN_MS + STEP_FASTER_MS) step_ms -= STEP_FASTER_MS;
            place_food();
        }
    }
}

static void game_over_screen(void) {
    char text[16];
    rectan(20, 40, 139, 95, COLOR_BG);
    drawtext(44, 46, "GAME OVER", COLOR_FOOD, COLOR_BG, 1);
    number_text(text, "SCORE ", score);
    drawtext(44, 60, text, COLOR_TEXT, COLOR_BG, 1);
    drawtext(26, 80, "OK: PLAY AGAIN", COLOR_TEXT, COLOR_BG, 1);
    delay_ms(500);                      // A key held at the crash does not skip it
    wait_ok();
}

void snake_run(void) {
    uint32_t size;
    uint8_t *buf = fountain_scratch_buffer(&size);
    body = (uint16_t *)(((uintptr_t)buf + 1u) & ~(uintptr_t)1u);   // 16-bit aligned
    occupied = (uint8_t *)(body + CELLS);
    rng_state = _CP0_GET_COUNT();
    best = 0;

    title_screen();
    while (true) {
        new_game();
        play();
        game_over_screen();
    }
}
