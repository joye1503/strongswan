/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup tun_device tun_device
 * @{ @ingroup networking
 */

#ifndef TUN_DEVICE_H_
#define TUN_DEVICE_H_

#include <networking/host.h>

#ifdef __WIN32__
/* capacity must be a power of two and between 128 kiB and 64 MiB */
#define TUN_PACKET_ALIGNMENT 4
#define TUN_RING_CAPACITY 64*1024*1024
#define TUN_RING_SIZE(TUN_RING, capacity) (sizeof(TUN_RING) + capacity + 0x10000)
#define TUN_MAX_IP_PACKET_SIZE 0xFFFF
#define PNP_INSTANCE_ID "{abcde}"
#define TUN_IOCTL_REGISTER_RINGS 0xca6ce5c0
#define TUN_PACKET_TRAILING_SIZE (sizeof(uint32_t) + ((TUN_MAX_IP_PACKET_SIZE + \
    (TUN_PACKET_ALIGNMENT - 1)) &~(TUN_PACKET_ALIGNMENT - 1)) - TUN_PACKET_ALIGNMENT)
#define TUN_WRAP_POSITION(position, size) (position & (size - 1))
#define TUN_PACKET_ALIGN(size) ((size + (TUN_PACKET_ALIGNMENT - 1)) &~(TUN_PACKET_ALIGNMENT - 1))
typedef struct _TUN_RING {
    volatile ULONG Head;
    volatile ULONG Tail;
    volatile LONG Alertable;
    UCHAR Data[TUN_RING_CAPACITY + TUN_PACKET_TRAILING_SIZE];
} TUN_RING;

typedef struct _TUN_REGISTER_RINGS {
    struct {
        ULONG RingSize;
        TUN_RING *Ring;
        HANDLE TailMoved;
    } Send, Receive;
    /* Send ring is for data from driver to application */
    /* Receive ring is for data from application to driver */
} TUN_REGISTER_RINGS;

typedef struct _TUN_PACKET {
    ULONG Size;
    UCHAR Data[TUN_MAX_IP_PACKET_SIZE];
} TUN_PACKET;
#endif
typedef struct tun_device_t tun_device_t;

/**
 * Class to create TUN devices
 *
 * Creating such a device requires the CAP_NET_ADMIN capability.
 */
struct tun_device_t {

	/**
	 * Read a packet from the TUN device
	 *
	 * @note This call blocks until a packet is available. It is a thread
	 * cancellation point.
	 *
	 * @param packet		the packet read from the device, allocated
	 * @return				TRUE if successful
	 */
	bool (*read_packet)(tun_device_t *this, chunk_t *packet);

	/**
	 * Write a packet to the TUN device
	 *
	 * @param packet		the packet to write to the TUN device
	 * @return				TRUE if successful
	 */
	bool (*write_packet)(tun_device_t *this, chunk_t packet);

	/**
	 * Set the IP address of the device
	 *
	 * @param addr			the desired interface address
	 * @param netmask		the netmask to use
	 * @return				TRUE if operation successful
	 */
	bool (*set_address)(tun_device_t *this, host_t *addr, uint8_t netmask);

	/**
	 * Get the IP address previously assigned to using set_address().
	 *
	 * @param netmask		pointer receiving the configured netmask, or NULL
	 * @return				address previously set, NULL if none
	 */
	host_t* (*get_address)(tun_device_t *this, uint8_t *netmask);

	/**
	 * Bring the TUN device up
	 *
	 * @return				TRUE if operation successful
	 */
	bool (*up)(tun_device_t *this);

	/**
	 * Set the MTU for this TUN device
	 *
	 * @param mtu			new MTU
	 * @return				TRUE if operation successful
	 */
	bool (*set_mtu)(tun_device_t *this, int mtu);

	/**
	 * Get the current MTU for this TUN device
	 *
	 * @return				current MTU
	 */
	int (*get_mtu)(tun_device_t *this);

	/**
	 * Get the interface name of this device
	 *
	 * @return				interface name
	 */
	char *(*get_name)(tun_device_t *this);

#ifdef __WIN32__
        /**
         * Get the underlying HANDLE.
         *
         * @return                              file HANDLE of this tun device
         */
        HANDLE (*get_handle)(tun_device_t *this);
#else
	/**
	 * Get the underlying tun file descriptor.
	 *
	 * @return				file descriptor of this tun device
	 */
	int (*get_fd)(tun_device_t *this);
#endif /* !__WIN32__ */
	/**
	 * Destroy a tun_device_t
	 */
	void (*destroy)(tun_device_t *this);

};

/**
 * Create a TUN device using the given name template.
 *
 * @param name_tmpl			name template, defaults to "tun%d" if not given
 * @return					TUN device
 */
tun_device_t *tun_device_create(const char *name_tmpl);

#endif /** TUN_DEVICE_H_ @}*/
