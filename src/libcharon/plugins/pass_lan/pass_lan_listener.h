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
 * @defgroup pass_lan_listener pass_lan_listener
 * @{ @ingroup pass_lan
 */

#ifndef PASS_LAN_LISTENER_H_
#define PASS_LAN_LISTENER_H_


#include <bus/listeners/listener.h>

typedef struct pass_lan_listener_t pass_lan_listener_t;

/*
 * Manage the local passthrough policies
 */
struct pass_lan_listener_t {

	/**
	 * Implements a listener.
	 */
	listener_t listener;

	/**
	 * Destroy a pass_lan_listener_t.
	 */
	void (*destroy)(pass_lan_listener_t *this);
};

/**
 * Create a pass_lan_listener instance.
 */
pass_lan_listener_t *pass_lan_listener_create();

#endif /** PASS_LAN_LISTENER_H_ @}*/
