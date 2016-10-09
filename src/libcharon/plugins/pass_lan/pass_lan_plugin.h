/*
 * Copyright (C) 2016 Noel Kuntze
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

/**
 * @defgroup pass_lan pass_lan
 * @ingroup cplugins
 *
 * @defgroup pass_lan_plugin pass_lan_plugin
 * @{ @ingroup pass_lan
 */

#ifndef PASS_LAN_PLUGIN_H_
#define PASS_LAN_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct pass_lan_plugin_t pass_lan_plugin_t;

/**
 * pass_lan plugin
 *
 * This plugin installs and uninstalls passthrough policies based on the
 * installed IP addresses on the network interfaces.
 *
 */
struct pass_lan_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** PASS_LAN_PLUGIN_H_ @}*/
