/*
 * Copyright (C) 2020 Noel Kuntze
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef WINDOWS_HELPER_H_
#define WINDOWS_HELPER_H_
#include <utils/utils.h>
#include <utils/compat/windows.h>

#include <synchapi.h>

#include <library.h>

/**
 * helper function for writing guids into character buffers
 * Thread safe and safe for calling several times.
 * Writes the GUID in XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXXXXXX form
 * @param		dst 	destination buffer for GUID. Has to be at least 37 characters in length.
 * @param		dst_len	length of destination buffer
 * @param		GUID 	GUID to transform into a string
 * @return				Boolean indicating success (buffer long enough) or failure (buffer too short)
 */
bool guid2string(char *dst, size_t dst_len, GUID *guid);

/**
 * helper function for getting registry values that may not exist yet
 * @param	key				registry key to query
 * @param	caller_buf 		caller supplied buffer for storing the queried value. Must be realloc()-atable
 *							If the function returns FALSE, the content of caller_buf is undefined.
 * @param	caller_buf_len	length of caller_buf in bytes.
 							Will contain the length of the written data in bytes after the function returns.
 							If the function returns FALSE, the content of caller_buf_len is undefined.
 * @param	reg_val_name	name of the value to query
 * @param	reg_val_type	Will contain the registry type of the value (MULTI_SZ, EXPAND_SZ, ...)
 * @param	timeout			time (in ms) to wait for the registry key to appear
 * @return					TRUE if querying succeeded, FALSE if not
 */
bool registry_wait_get_value(HKEY key, void *caller_buf, size_t *caller_buf_len, char *reg_val_name, DWORD *reg_val_type,
			size_t timeout);

/**
 * Helper function for expanding strings containing environmental variables in Windows %var% format.
 * Warning: This function silently fails to expand the string if realloc() fails.
 * @param	buf 			source buffer to get the original string from
 * @param 	buf_len 		length of the buffer in bytes
 * @param	new_buf_len		variable to store the length of the new buffer in (length is in bytes)
 */
char *windows_expand_string(char *buf, size_t *buf_len, size_t *new_buf_len);

#endif