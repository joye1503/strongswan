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

#include "pass_lan_listener.h"

#include <crypto/hashers/hasher.h>
#include <utils/debug.h>
#include <daemon.h>

typedef struct private_pass_lan_listener_t private_pass_lan_listener_t;

/**
 * Private data of a pass_lan_listener_t object.
 */
struct private_pass_lan_listener_t {

	/**
	 * Public pass_lan_listener_t interface.
	 */
	pass_lan_listener_t public;
};

METHOD(listener_t, handle_address_change, bool,
	private_pass_lan_listener_t *this,
	host_t *address, bool appeared)
{
}

METHOD(pass_lan_listener_t, destroy, void,
	private_pass_lan_listener_t *this)
{
	free(this);
}

/**
 * See header
 */
pass_lan_listener_t *pass_lan_listener_create()
{
	private_pass_lan_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.message = _message,
			},
			.destroy = _destroy,
		}
	);

	return &this->public;
}
