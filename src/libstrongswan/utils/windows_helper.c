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

#include "windows_helper.h"

/**
 * See header
 */
bool guid2string(char *dst, size_t dst_len, GUID *guid)
{
	size_t ret = 0;
	if(dst_len <= 37)
	{
		ret = snprintf(dst, dst_len,
			"%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			guid->Data1, guid->Data2, guid->Data3,	
			guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
			guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);

	}
	return ret == 37 ? TRUE : FALSE;
}

bool guidfromstring(GUID *guid, char *str)
{
    size_t read = scanf("%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        guid->Data1, guid->Data2, guid->Data3,	
			guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
			guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    return read == 36 ? TRUE :  FALSE;
}
/**
 * see header
 */
bool registry_wait_get_value(HKEY key, void *caller_buf, DWORD *caller_buf_len,
	char *reg_val_name, DWORD *reg_val_type, size_t timeout)
{
	/* timeout is in ms */
	timeval_t now, deadline;
	DWORD own_ret = FALSE, function_ret_query, function_ret_wait;
	char buf[512];
	HANDLE handle = CreateEventA(
		NULL,
		FALSE,
		FALSE,
		NULL
		);
	if (!handle)
	{
		char buf[512];
		dlerror_mt(buf, sizeof(buf));
		DBG1(DBG_LIB, "Failed to create handle: %s", buf);
		return FALSE;
	}	
	/* Get current time, add timeout */
	time_monotonic(&deadline);
	timeval_add_ms(&deadline, timeout);

	while(TRUE)
	{
		/* Try to get value */
		function_ret_query = RegQueryValueExA(key, reg_val_name, NULL, reg_val_type, caller_buf, (LPDWORD) caller_buf_len);
		switch(function_ret_query)
		{
			case ERROR_FILE_NOT_FOUND:
			case ERROR_PATH_NOT_FOUND:
				time_monotonic(&now);
				/* All vars in this calculation are signed, so no issues
				 * until the first part overflows (certainly farther in the future than this code will run)
				 */
				int64_t ms_to_deadline = (deadline.tv_sec - now.tv_sec) * 1000 + (deadline.tv_usec - now.tv_usec);
				if (ms_to_deadline <= 0)
				{
					DBG1(DBG_LIB, "Timed out waiting for registry value %s", reg_val_name);
					break;
					break;
				}
				/* Set up handle for notify */
				if (!RegNotifyChangeKeyValue(key, FALSE, REG_NOTIFY_CHANGE_LAST_SET, handle, true))
				{
					dlerror_mt(buf, sizeof(buf));
					DBG1(DBG_LIB, "Failed to call RegNotifyChangeKeyValue: %s", buf);
					break;
					break;
				}
				function_ret_wait = WaitForSingleObjectEx(handle, ms_to_deadline, FALSE);
				if(function_ret_wait != WAIT_OBJECT_0)
				{
					dlerror_mt(buf, sizeof(buf));
					DBG1(DBG_LIB, "Failed to wait for event (WaitForSingleObjectEx(): %ld): %s", function_ret_wait, buf);
					break;
					break;
				}
				break;
			case ERROR_MORE_DATA:
				caller_buf = realloc(caller_buf, *caller_buf_len);
				break;
			case TRUE:
				/* succeeded */
				own_ret = TRUE;
				break;
				break;
			default:
				dlerror_mt(buf, sizeof(buf));
				DBG1(DBG_LIB, "Failed to read registry value (RegQueryValueExA): %s", buf);
				break;
				break;
		}
	}
	if(caller_buf)
	{
		free(caller_buf);
	}
	CloseHandle(handle);
	return own_ret;
}

/**
 * Described in header.
 */
char *windows_expand_string(char *buf, DWORD *buf_len, size_t *new_buf_len)
{
	size_t new_length = *buf_len, required_size;
	char *intermediate_buf = NULL;

	for(size_t i=0;i<=2;i++)
	{
		intermediate_buf = realloc(intermediate_buf, new_length);
		required_size = ExpandEnvironmentStringsA(buf, intermediate_buf, new_length);
		if (required_size > new_length)
		{
			new_length = required_size;
		} else {
			break;
		}
	}
	*new_buf_len = new_length;
	return intermediate_buf;
}

/**
 * Described in header.
 */
HKEY registry_open_wait(HKEY key, char *path, DWORD access, size_t timeout)
{
	/* timeout is in ms */
	HKEY intermediate = NULL;
	char buf[512];
	timeval_t now, deadline;
	DWORD function_ret_wait;
	char *str = path, *tok, *current_path = NULL, *last_part;
	/* Number of iterations */
	size_t cnt = 0, current_path_len = 0, old_path_len = 0, tok_len;
	linked_list_t *tokens = strsplit(path, "\\");
	tokens->get_last(tokens, (void **) &last_part);
	enumerator_t *enumerator = tokens->create_enumerator(tokens);
	HANDLE handle = CreateEventA(
		NULL,
		FALSE,
		FALSE,
		NULL
	);

	if (!handle)
	{
		char buf[512];
		dlerror_mt(buf, sizeof(buf));
		DBG1(DBG_LIB, "Failed to create handle: %s", buf);
		return FALSE;
	}	

	/* Get current time, add timeout */
	time_monotonic(&deadline);
	timeval_add_ms(&deadline, timeout);	
	/* In the loop, we check if each key occuring in the path is accessible.
	 * If a key is not, it will be created by the installation routine
	 * that was called before this function.
	 * This means that we instead wait for an event in the registry in
	 * which the key was created.
	 * This function is written under the presumption that the large
	 * majority of the path is accessible already
	 * and thus the contents of the switch case for 
	 * RROR_PATH_NOT_FOUND and ERROR_FILE_NOT_FOUND are only called
	 * seldomly. It was written with saving syscalls in mind.
	 */
	while (enumerator->enumerate(enumerator, &tok))
	{
		if (tok)
		{
			/* 
			 * FIXME: Need to proactively check if this is the final
			 * path name so we can use a different access rights
			 * bitmask instead of NOTIFY
			 */
			old_path_len = current_path_len;
			tok_len = strlen(tok);
			str += tok_len + 1;
			current_path_len += tok_len + 1;
			current_path = realloc(current_path, current_path_len+1);
			/* Add the new token to the path*/
			strncat(current_path+old_path_len, tok, tok_len-1);
			/* Check if the current path is accessible */
			if (last_part == tok)
			{
				access = KEY_NOTIFY;
			}
			
			switch(RegOpenKeyA(key, current_path, &intermediate))
			{
				case ERROR_SUCCESS:
				break;
				case ERROR_FILE_NOT_FOUND:
				case ERROR_PATH_NOT_FOUND:
					time_monotonic(&now);
					/* All vars in this calculation are signed, so no issues
					 * until the first part overflows (certainly farther in the future than this code will run)
					 */
					int64_t ms_to_deadline = (deadline.tv_sec - now.tv_sec) * 1000 + (deadline.tv_usec - now.tv_usec);
					if (ms_to_deadline <= 0)
					{
						DBG1(DBG_LIB, "Timed out waiting for registry value %s", current_path);
						break;
						break;
					}
					/* Setup notifier */
					if (!RegNotifyChangeKeyValue(key, FALSE, REG_NOTIFY_CHANGE_NAME, handle, true))
					{
						dlerror_mt(buf, sizeof(buf));
						DBG1(DBG_LIB, "Failed to setup notify handle for REG_NOTIFY_CHANGE_NAME on %s using RegNotifyChangeKeyValue: %s", current_path, buf);
						goto cleanup;
					}
					/* Check if we can access the key */
					switch(RegOpenKeyExA(key, current_path, 0, access, &intermediate))
					{
						case ERROR_SUCCESS:
							/* Close the notifier handle again and open a new one, just in case the kernel handles reusing of active handles badly.*/
							CloseHandle(handle);
							handle = CreateEventA(
								NULL,
								FALSE,
								FALSE,
								NULL
							);

							if (!handle)
							{
								dlerror_mt(buf, sizeof(buf));
								DBG1(DBG_LIB, "Failed to create handle: %s", buf);
								goto cleanup;
							}
							break;
						case ERROR_FILE_NOT_FOUND:
						case ERROR_PATH_NOT_FOUND:
							time_monotonic(&now);
							/* All vars in this calculation are signed, so no issues
							 * until the first part overflows (certainly farther in the future than this code will run)
							 */
							int64_t ms_to_deadline = (deadline.tv_sec - now.tv_sec) * 1000 + (deadline.tv_usec - now.tv_usec);
							if (ms_to_deadline <= 0)
							{
								DBG1(DBG_LIB, "Timed out waiting for registry value %s", current_path);
								goto cleanup;
							}
							function_ret_wait = WaitForSingleObjectEx(handle, ms_to_deadline, FALSE);
							if(function_ret_wait != WAIT_OBJECT_0)
							{
								dlerror_mt(buf, sizeof(buf));
								DBG1(DBG_LIB, "Failed to wait for event (WaitForSingleObjectEx(): %ld): %s", function_ret_wait, buf);
								goto cleanup;
							}
							break;
						default:
							dlerror_mt(buf, sizeof(buf));
							DBG1(DBG_LIB, "Failed to open registry value (RegOpenKeyEx): %s", buf);
							goto cleanup;
							break;
					}
					break;
				default:
					dlerror_mt(buf, sizeof(buf));
					DBG1(DBG_LIB, "Failed to open registry key %s (RegOpenKeyA): %s", current_path, buf);
					goto cleanup;
					break;
			}
		}
		cnt++;
	}

cleanup: ;
	tokens->reset_enumerator(tokens, enumerator);
	while(enumerator->enumerate(enumerator, str))
	{
		free(str);
	}
	enumerator->destroy(enumerator);
	tokens->destroy(tokens);
	if(current_path)
	{
		free(current_path);
	}
	CloseHandle(handle);
	return intermediate;
}

bool check_reboot(HDEVINFO dev_info_set, SP_DEVINFO_DATA *dev_info_data)
{
	SP_DEVINSTALL_PARAMS dev_install_params = {
		.cbSize = sizeof(SP_DEVINSTALL_PARAMS)
	};
	bool ret = SetupDiGetDeviceInstallParamsA(dev_info_set, dev_info_data, &dev_install_params);
	return dev_install_params.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART) & ret;
}
