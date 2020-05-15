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

/* 
 * File:   windows_tun.h
 * Author: thermi
 *
 * Created on 27. April 2020, 14:58
 */

#ifndef WINDOWS_TUN_H
#define WINDOWS_TUN_H

#include "tun_device.h"

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
char *windows_drv_info_get_next_hardwareid(char *pile, size_t *offset);

/*
 * Helper function that wraps around windows_drv_info_get_next_hardwareid.
 * It returns true if needle is in the pile (pile is a linear, empty string terminated array of strings).
 * It returns false if needle is NOT in the pile.
 *
 * @param pile			A linear array of strings. Terminated by an empty string.
 * @param needle		A string to find in pile.
 *
 * @return				Returns whether needle is in pile
 */
bool find_matching_hardwareid(char *pile, char* needle);

/*
 * Helper function for getting a nice human readable name for a specific device.
 * @param buffer                Allocated buffer that receives the device name.
 * @param buf_len               Length of the buffer in bytes.
 * @param dev_info_set          device info set that contains the device
 * @param dev_info_data         Data
 * @return                      zero byte terminated friendly name. Same as buffer.
 */
char *windows_setupapi_get_friendly_name(char *buffer, size_t buf_len, HDEVINFO dev_info_set, SP_DEVINFO_DATA *dev_info_data);


/*
 * Helper function for transforming double zero byte terminated string array to linked_list_t
 * @param pile                  double zero byte terminated string array
 * @return                      linked_list_t with copied strings of the string array, heap allocated
 */
linked_list_t *string_array_to_linked_list(char *pile);

/*
 * Implementation of tun_device_create for Windows.
 * @param name_tmpl     zero byte terminated string that contains the name template for the interface.
 */
tun_device_t *tun_device_create(const char *name_tmpl);


#endif /* WINDOWS_TUN_H */

