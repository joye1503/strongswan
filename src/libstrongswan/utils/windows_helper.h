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
 * helper function for reading GUIDs in string form (without the {}) into a GUID type structure.
 * Thread safe and safe for calling several times.
 * @param               guid    allocated GUID type structure, will receive the data from the GUID
 * @param               str     source string to read into the GUID type structure
 * @return                      Boolean indicating success or failure (string too short or not a valid GUID)
 */
bool guidfromstring(GUID *guid, char *str);

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
bool registry_wait_get_value(HKEY key, void *caller_buf, DWORD *caller_buf_len, char *reg_val_name, DWORD *reg_val_type,
			size_t timeout);

/**
 * helper function for waiting until the specified path exists (is accessible)
 * @param       key           root registry key
 * @param       path          complete path starting under the root registry key
 * @param       access        unused
 * @param       timeout       maximum time to wait for the key to be accessible
 * @return                    Whether the key is accessible within the timeout or not
 */
HKEY registry_open_wait(HKEY key, char *path, DWORD access, size_t timeout);

/**
 * Helper function for expanding strings containing environmental variables in Windows %var% format.
 * Warning: This function silently fails to expand the string if realloc() fails.
 * @param	buf 			source buffer to get the original string from
 * @param 	buf_len 		length of the buffer in bytes
 * @param	new_buf_len		variable to store the length of the new buffer in (length is in bytes)
 * @return                             Heap allocated string containing th expanded string.
 */
char *windows_expand_string(char *buf, DWORD *buf_len, size_t *new_buf_len);

/**
 * Helper function for checking if the specified device requires a reboot to complete installation.
 * @param       dev_info_set    HDEVINFO type struct containing the device
 * @param       dev_info_data   pointer to the struct containing the device
 * @return                      State whether a reboot is required or not.
 */
bool check_reboot(HDEVINFO dev_info_set, SP_DEVINFO_DATA *dev_info_data);
#endif