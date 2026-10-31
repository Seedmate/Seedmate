/*******************************************************************************
 * Project:     SeedMate
 * File:        snake.h
 *
 * Summary:
 *   Snake game shown as a decoy at power-on.
 *
 * Description:
 *   Unless OK + RIGHT are held while the device starts, main() runs the game
 *   instead of the Seedmate app, so the device looks like a toy. The game
 *   never returns: the real app needs a restart with the key combination.
 *   It uses no secret data, no SD card and no scanner, and keeps its board
 *   in the fountain part buffer (unused while it runs), so it costs no RAM.
 *   Fullscreen game: exempt from the button grid and color rules (6, 7),
 *   on purpose, so nothing on screen looks like the Seedmate interface.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#ifndef SNAKE_H
#define SNAKE_H

#define DECOY_SNAKE 1           // 0: the app starts without the key combination

// Runs the game forever
void snake_run(void);

#endif // SNAKE_H
