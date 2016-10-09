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


#include "pass_lan_plugin.h"
#include "pass_lan_listener.h"

#include <daemon.h>

typedef struct private_pass_lan_plugin_t private_pass_lan_plugin_t;

/**
 * Private data of a pass_lan_plugin_t object.
 */
struct private_pass_lan_plugin_t {

	/**
	 * Public pass_lan_plugin_t interface.
	 */
	pass_lan_plugin_t public;

	/**
	 * handle_address_change listener adding and removing passthrough policies
	 */
	pass_lan_listener_t *pass_lan;
};

METHOD(plugin_t, get_name, char*,
	private_pass_lan_plugin_t *this)
{
	return "pass_lan";
}

/**
 * Register listener
 */
static bool plugin_cb(private_pass_lan_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		this->pass_lan = pass_lan_listener_create();
		if (this->pass_lan)
		{
			charon->bus->add_listener(charon->bus, &this->pass_lan->listener);
		}
	}
	else
	{
		if (this->pass_lan)
		{
			charon->bus->remove_listener(charon->bus, &this->pass_lan->listener);
			this->pass_lan->destroy(this->pass_lan);
		}
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_pass_lan_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "pass_lan")
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_pass_lan_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *pass_lan_plugin_create()
{
	private_pass_lan_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
