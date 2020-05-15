/*
 * Copyright (C) 2020 Noel Kuntze <noel.kuntze@thermi.consulting>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <winsock2.h>
#include <windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <devpkey.h>
#include <winreg.h>
#include <utils/windows_helper.h>
#include <ddk/ndisguid.h>

#include "../utils/utils/memory.h"
#include "../collections/linked_list.h"

#include "windows_tun.h"
#include "wintun_support.h"

/* Stub. */
struct private_openvpn_tun_device_t {
	uint64_t foo;
} typedef private_openvpn_tun_device_t;

 /*
 * Helper function to get the next HardwareID in the
 * SP_DRVINFO_DETAIL_DATA_A.HardwareID linear array.
 * (Looks like this: "abcdef\0ghijkl\0mnopqrs\0\0". Empty string (Just a NULL byte)
 * denotes the end of the array)
 *
 * @param pile			linear character array of the hardwareIDs as they are part of
 *						the SP_DRVINFO_DETAIL_DATA_A struct.
 * @param offset		pointer to a location in which the end position of the search algorithm is stored.
 *						It is used to keep the offset between multiple calls of the function and ease its use.
 *						The value is the position at which the resulting string ends (strlen() + 1, or its NULL byte)
 * @return				The next hardwareID or NULL, if the end of the array was reached.
 */
char *windows_drv_info_get_next_hardwareid(char *pile, size_t *offset)
{
	size_t len = 0, old_offset = 0;
	while(true)
	{
		old_offset = *offset;
		len = strlen(pile + *offset);
		*offset += len + 1;
		
		if (len == 0)
		{
			/* End of the list, empty string. */
			return NULL;
		}

		return pile + old_offset;
	}
}

/*
 * Helper function that wraps around windows_drv_info_get_next_hardwareid.
 * It returns true if needle is in the pile (pile is a linear, empty string terminated array of strings).
 * It returns false if needle is NOT in the pile.
 *
 * @param pile			A linear array of strings. Terminated by an empty string.
 * @param needle		A string to find in pile.
 *
 * @returns				Returns whether needle is in pile
 */
bool find_matching_hardwareid(char *pile, char* needle)
{
	size_t offset = 0;
	char *item;
	while(true)
	{
		item = windows_drv_info_get_next_hardwareid(pile, &offset);
		if (!item)
		{
			return false;
		}

		if(strcmp(item, needle) == 0)
		{
			return true;
		}
	}
}

char *windows_setupapi_get_friendly_name(char *buffer, size_t buf_len, HDEVINFO dev_info_set, SP_DEVINFO_DATA *dev_info_data)
{
	memwipe(buffer, buf_len);
	size_t required_length;
        DWORD prop_type;
	if(!SetupDiGetDeviceRegistryPropertyA(
		dev_info_set, dev_info_data,
		SPDRP_FRIENDLYNAME,
		&prop_type,
		buffer,
		buf_len,
		(DWORD *)&required_length
		))
	{
		/* Try hardware path instead */
		SetupDiGetDeviceRegistryPropertyA(
			dev_info_set, dev_info_data,
			SPDRP_LOCATION_INFORMATION,
			&prop_type,
			buffer,
			buf_len,
			(DWORD *)&required_length);
		return buffer;
	}
	return buffer;
}

/* Described in header */
linked_list_t *string_array_to_linked_list(char *pile)
{
	linked_list_t *list = linked_list_create();
	size_t offset = 0;
	char *item;
	while(true)
	{
		item = windows_drv_info_get_next_hardwareid(pile, &offset);
		if (!item)
		{
			return list;
		}
		list->insert_last(list, item);
	}
	return list;
}

/* Stub */
tun_device_t *try_configure_openvpn(const char *name_tmpl)
{
	return NULL;
}
/*
 * Described in header
 */

tun_device_t *tun_device_create(const char *name_tmpl)
{
	tun_device_t *public = try_configure_wintun(name_tmpl);
	/* if (!public)
	{
		public = try_configure_openvpn(name_tmpl);
	} */
	if(!public)
	{
		DBG1(DBG_LIB, "failed to create TUN device.");
		return NULL;
	}
	DBG1(DBG_LIB, "created TUN device: %s", public->get_name(public));
	return public;
}
