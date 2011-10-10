/*
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
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
 * @defgroup plugin_feature plugin_feature
 * @{ @ingroup plugins
 */

#ifndef PLUGIN_FEATURE_H_
#define PLUGIN_FEATURE_H_

typedef struct plugin_feature_t plugin_feature_t;

#include <library.h>
#include <eap/eap.h>
#include <plugins/plugin.h>

/**
 * Callback function of a plugin to (un-)register a specified feature.
 *
 * @param plugin			plugin instance
 * @param feature			feature to register
 * @param reg				TRUE to register, FALSE to unregister
 * @param cb_data			user data passed with callback function
 * @return					TRUE if registered successfully
 */
typedef bool (*plugin_feature_callback_t)(plugin_t *plugin,
										  plugin_feature_t *feature,
										  bool reg,void *cb_data);

/**
 * Feature a plugin provides or depends on, including registration functions.
 *
 * Each plugin returns a list of plugin features, allowing the plugin loader
 * to resolve dependencies and register the feature. FEATURE_PROVIDE defines
 * features provided by the plugin, hard (DEPENDS) or soft (SDEPEND) dependency
 * specified is related to the previously defined PROVIDE feature.
 * If a plugin feature requires to hook in functionality into the library
 * or a daemon, it can use REGISTER or CALLBACK entries. Each PROVIDED feature
 * uses the REGISTER/CALLBACK entry defined previously. The REGISTER entry
 * defines a common feature registration function directly passed to the
 * associated manager or factory (crypto/credential factory etc.). A callback
 * function is more generic allows the loader to invoke a callback to do
 * the registration.
 *
 * To conviently create feature lists, use the four macros PLUGIN_REGISTER,
 * PLUGIN_CALLBACK, PLUGIN_PROVIDE, PLUGIN_DEPENDS and PLUGIN_SDEPEND. Use
 * identation to show how the registration functions and dependencies are
 * related to a provided feature, such as:
 *
 * @verbatim
	// two features, one with two dependencies, both use a callback to register
	PLUGIN_CALLBACK(...),
		PLUGIN_PROVIDE(...),
			PLUGIN_DEPENDS(...),
			PLUGIN_SDEPEND(...),
		PLUGIN_PROVIDE(...),
	// common constructor to register for a feature with one dependency
	PLUGIN_REGISTER(...),
		PLUGIN_PROVIDE(...),
			PLUGIN_DEPENDS(...),
	// feature that does not use a registration function
	PLUGIN_PROVIDE(...),
	@endverbatim
 */
struct plugin_feature_t {
	/** kind of entry */
	enum {
		/* plugin provides this feature */
		FEATURE_PROVIDE,
		/* a feature depends on this feature, hard dependency */
		FEATURE_DEPENDS,
		/* a feature can optionally use this feature, soft dependency */
		FEATURE_SDEPEND,
		/* register the specified function for all following features */
		FEATURE_REGISTER,
		/* use a callback to register all following features */
		FEATURE_CALLBACK,
	} kind;
	/* type of feature */
	enum {
		/** not a feature */
		FEATURE_NONE,
		/** crypter_t */
		FEATURE_CRYPTER,
		/** aead_t */
		FEATURE_AEAD,
		/** signer_t */
		FEATURE_SIGNER,
		/** hasher_t */
		FEATURE_HASHER,
		/** prf_t */
		FEATURE_PRF,
		/** diffie_hellman_t */
		FEATURE_DH,
		/** rng_t */
		FEATURE_RNG,
		/** generic private key support */
		FEATURE_PRIVKEY,
		/** generating new private keys */
		FEATURE_PRIVKEY_GEN,
		/** private_key_t->sign() */
		FEATURE_PRIVKEY_SIGN,
		/** private_key_t->decrypt() */
		FEATURE_PRIVKEY_DECRYPT,
		/** generic public key support */
		FEATURE_PUBKEY,
		/** public_key_t->verify() */
		FEATURE_PUBKEY_VERIFY,
		/** public_key_t->encrypt() */
		FEATURE_PUBKEY_ENCRYPT,
		/** parsing certificates */
		FEATURE_CERT_DECODE,
		/** generating certificates */
		FEATURE_CERT_ENCODE,
		/** EAP server implementation */
		FEATURE_EAP_SERVER,
		/** EAP peer implementation */
		FEATURE_EAP_PEER,
		/** database_t */
		FEATURE_DATABASE,
		/** fetcher_t */
		FEATURE_FETCHER,
		/** custom feature, described with a string */
		FEATURE_CUSTOM,
	} type;
	/** More specific data for each type */
	union {
		/** FEATURE_CRYPTER */
		struct {
			encryption_algorithm_t alg;
			size_t key_size;
		} crypter;
		/** FEATURE_AEAD */
		struct {
			encryption_algorithm_t alg;
			size_t key_size;
		} aead;
		/** FEATURE_SIGNER */
		integrity_algorithm_t signer;
		/** FEATURE_PRF */
		pseudo_random_function_t prf;
		/** FEATURE_HASHER */
		hash_algorithm_t hasher;
		/** FEATURE_DH */
		diffie_hellman_group_t dh_group;
		/** FEATURE_RNG */
		rng_quality_t rng_quality;
		/** FEATURE_PRIVKEY */
		key_type_t privkey;
		/** FEATURE_PRIVKEY_GEN */
		key_type_t privkey_gen;
		/** FEATURE_PRIVKEY_SIGN */
		signature_scheme_t privkey_sign;
		/** FEATURE_PRIVKEY_DECRYPT */
		encryption_scheme_t privkey_decrypt;
		/** FEATURE_PUBKEY */
		key_type_t pubkey;
		/** FEATURE_PUBKEY_VERIFY */
		signature_scheme_t pubkey_verify;
		/** FEATURE_PUBKEY_ENCRYPT */
		encryption_scheme_t pubkey_encrypt;
		/** FEATURE_CERT_DECODE/ENCODE */
		certificate_type_t cert;
		/** FEATURE_EAP_SERVER/CLIENT */
		eap_type_t eap;
		/** FEATURE_DATABASE */
		db_driver_t database;
		/** FEATURE_FETCHER */
		char *fetcher;
		/** FEATURE_CUSTOM */
		char *custom;

		/** FEATURE_REGISTER */
		struct {
			/** feature specific function to register for this type */
			void *f;
			/** final flag to pass for builder_function_t */
			bool final;
		} reg;

		/** FEATURE_CALLBACK */
		struct {
			/** callback function to invoke for registration */
			plugin_feature_callback_t f;
			/** data to pass to callback */
			void *data;
		} cb;
	} arg;
};

#define FEATURE(kind, type, ...) _PLUGIN_FEATURE_##type(kind, __VA_ARGS__)

/**
 * Define function to register directly for all upcoming features.
 *
 * @param type		feature type to register
 * @param f			type specific function to register
 * @param ...		type specific additional arguments
 */
#define PLUGIN_REGISTER(type, f, ...) _PLUGIN_FEATURE_REGISTER_##type(type, f, ##__VA_ARGS__)

/**
 * Define a callback to invoke for registering all upcoming features.
 *
 * @param cb		type specific callback function to register
 * @param data		data pointer to pass to callback
 */
#define PLUGIN_CALLBACK(cb, data) _PLUGIN_FEATURE_CALLBACK(cb, data)

/**
 * Define a feature the plugin provides.
 *
 * @param type		feature type to provide
 * @param ...		type specific arguments
 */
#define PLUGIN_PROVIDE(type, ...) _PLUGIN_FEATURE_##type(PROVIDE, __VA_ARGS__)

/**
 * Define a hard dependency for the previously defined feature.
 *
 * @param type		feature type to provide
 * @param ...		type specific arguments
 */
#define PLUGIN_DEPENDS(type, ...) _PLUGIN_FEATURE_##type(DEPENDS, __VA_ARGS__)

/**
 * Define a soft dependency for the previously defined feature.
 *
 * @param type		feature type to provide
 * @param ...		type specific arguments
 */
#define PLUGIN_SDEPEND(type, ...) _PLUGIN_FEATURE_##type(SDEPEND, __VA_ARGS__)

#define __PLUGIN_FEATURE(kind, type, ...)					(plugin_feature_t){ FEATURE_##kind, FEATURE_##type, { __VA_ARGS__ }}
#define _PLUGIN_FEATURE_CRYPTER(kind, alg, size)			__PLUGIN_FEATURE(kind, CRYPTER, .crypter = { alg, size })
#define _PLUGIN_FEATURE_AEAD(kind, alg, size)				__PLUGIN_FEATURE(kind, AEAD, .aead = { alg, size })
#define _PLUGIN_FEATURE_SIGNER(kind, alg)					__PLUGIN_FEATURE(kind, SIGNER, .signer = alg)
#define _PLUGIN_FEATURE_HASHER(kind, alg)					__PLUGIN_FEATURE(kind, HASHER, .hasher = alg)
#define _PLUGIN_FEATURE_PRF(kind, alg)						__PLUGIN_FEATURE(kind, PRF, .prf = alg)
#define _PLUGIN_FEATURE_DH(kind, group)						__PLUGIN_FEATURE(kind, DH, .dh_group = group)
#define _PLUGIN_FEATURE_RNG(kind, quality)					__PLUGIN_FEATURE(kind, RNG, .rng_quality = quality)
#define _PLUGIN_FEATURE_PRIVKEY(kind, type)					__PLUGIN_FEATURE(kind, PRIVKEY, .privkey = type)
#define _PLUGIN_FEATURE_PRIVKEY_GEN(kind, type)				__PLUGIN_FEATURE(kind, PRIVKEY_GEN, .privkey_gen = type)
#define _PLUGIN_FEATURE_PRIVKEY_SIGN(kind, scheme)			__PLUGIN_FEATURE(kind, PRIVKEY_SIGN, .privkey_sign = scheme)
#define _PLUGIN_FEATURE_PRIVKEY_DECRYPT(kind, scheme)		__PLUGIN_FEATURE(kind, PRIVKEY_DECRYPT, .privkey_decrypt = scheme)
#define _PLUGIN_FEATURE_PUBKEY(kind, type)					__PLUGIN_FEATURE(kind, PUBKEY, .pubkey = type)
#define _PLUGIN_FEATURE_PUBKEY_VERIFY(kind, scheme)			__PLUGIN_FEATURE(kind, PUBKEY_VERIFY, .pubkey_verify = scheme)
#define _PLUGIN_FEATURE_PUBKEY_ENCRYPT(kind, scheme)		__PLUGIN_FEATURE(kind, PUBKEY_ENCRYPT, .pubkey_encrypt = scheme)
#define _PLUGIN_FEATURE_CERT_DECODE(kind, type)				__PLUGIN_FEATURE(kind, CERT_DECODE, .cert = type)
#define _PLUGIN_FEATURE_CERT_ENCODE(kind, type)				__PLUGIN_FEATURE(kind, CERT_ENCODE, .cert = type)
#define _PLUGIN_FEATURE_EAP_SERVER(kind, type)				__PLUGIN_FEATURE(kind, EAP_SERVER, .eap = type)
#define _PLUGIN_FEATURE_EAP_PEER(kind, type)				__PLUGIN_FEATURE(kind, EAP_PEER, .eap = type)
#define _PLUGIN_FEATURE_DATABASE(kind, type)				__PLUGIN_FEATURE(kind, DATABASE, .database = type)
#define _PLUGIN_FEATURE_FETCHER(kind, type)					__PLUGIN_FEATURE(kind, FETCHER, .fetcher = type)

#define __PLUGIN_FEATURE_REGISTER(type, _f)					(plugin_feature_t){ FEATURE_REGISTER, FEATURE_##type, .arg.reg.f = _f }
#define __PLUGIN_FEATURE_REGISTER_BUILDER(type, _f, _final)	(plugin_feature_t){ FEATURE_REGISTER, FEATURE_##type, .arg.reg = {.f = _f, .final = _final, }}
#define _PLUGIN_FEATURE_REGISTER_CRYPTER(type, f)			__PLUGIN_FEATURE_REGISTER(type, f)
#define _PLUGIN_FEATURE_REGISTER_AEAD(type, f)				__PLUGIN_FEATURE_REGISTER(type, f)
#define _PLUGIN_FEATURE_REGISTER_SIGNER(type, f)			__PLUGIN_FEATURE_REGISTER(type, f)
#define _PLUGIN_FEATURE_REGISTER_HASHER(type, f)			__PLUGIN_FEATURE_REGISTER(type, f)
#define _PLUGIN_FEATURE_REGISTER_PRF(type, f)				__PLUGIN_FEATURE_REGISTER(type, f)
#define _PLUGIN_FEATURE_REGISTER_DH(type, f)				__PLUGIN_FEATURE_REGISTER(type, f)
#define _PLUGIN_FEATURE_REGISTER_RNG(type, f)				__PLUGIN_FEATURE_REGISTER(type, f)
#define _PLUGIN_FEATURE_REGISTER_PRIVKEY(type, f, final)	__PLUGIN_FEATURE_REGISTER_BUILDER(type, f, final)
#define _PLUGIN_FEATURE_REGISTER_PRIVKEY_GEN(type, f, final)__PLUGIN_FEATURE_REGISTER_BUILDER(type, f, final)
#define _PLUGIN_FEATURE_REGISTER_PUBKEY(type, f, final)		__PLUGIN_FEATURE_REGISTER_BUILDER(type, f, final)
#define _PLUGIN_FEATURE_REGISTER_CERT_DECODE(type, f, final)__PLUGIN_FEATURE_REGISTER_BUILDER(type, f, final)
#define _PLUGIN_FEATURE_REGISTER_CERT_ENCODE(type, f, final)__PLUGIN_FEATURE_REGISTER_BUILDER(type, f, final)
#define _PLUGIN_FEATURE_REGISTER_DATABASE(type, f)			__PLUGIN_FEATURE_REGISTER(type, f)
#define _PLUGIN_FEATURE_REGISTER_FETCHER(type, f)			__PLUGIN_FEATURE_REGISTER(type, f)

#define _PLUGIN_FEATURE_CALLBACK(_cb, _data) (plugin_feature_t){ FEATURE_CALLBACK, FEATURE_NONE, .arg.cb = { .f = _cb, .data = _data } }

/**
 * Names for plugin_feature_t types.
 */
extern enum_name_t *plugin_feature_names;

/**
 * Check if feature a matches to feature b.
 *
 * @param a			feature to check
 * @param b			feature to match against
 * @return			TRUE if a matches b
 */
bool plugin_feature_matches(plugin_feature_t *a, plugin_feature_t *b);

/**
 * Get a string describing feature.
 *
 * @param feature	feature to describe
 * @return			allocated string describing feature
 */
char* plugin_feature_get_string(plugin_feature_t *feature);

/**
 * Load a plugin feature using a REGISTER/CALLBACK feature entry.
 *
 * @param plugin	plugin providing feature
 * @param feature	feature to load
 * @param reg		REGISTER/CALLBACK feature entry to use for registration
 */
bool plugin_feature_load(plugin_t *plugin, plugin_feature_t *feature,
						 plugin_feature_t *reg);

/**
 * Unload a plugin feature using a REGISTER/CALLBACK feature entry.
 *
 * @param plugin	plugin providing feature
 * @param feature	feature to unload
 * @param reg		REGISTER/CALLBACK feature entry to use for deregistration
 */
bool plugin_feature_unload(plugin_t *plugin, plugin_feature_t *feature,
						   plugin_feature_t *reg);

#endif /** PLUGIN_FEATURE_H_ @}*/
