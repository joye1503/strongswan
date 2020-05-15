/*
 * Copyright (C) 2020 thermi
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
 * File:   wintun_support.h
 * Author: thermi
 *
 * Created on 12. Mai 2020, 23:04
 */

#ifndef WINTUN_SUPPORT_H
#        define WINTUN_SUPPORT_H

#        ifdef __cplusplus
extern "C" {
#        endif

#include "windows_tun.h"
#include "tun_device.h"

tun_device_t *try_configure_wintun(const char *name_tmpl);

#        ifdef __cplusplus
}
#        endif

#endif /* WINTUN_SUPPORT_H */

