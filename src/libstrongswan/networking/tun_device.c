/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * HSR Hochschule fuer Technik Rapperswil
 * Copyright (C) 2012 Martin Willi
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

#if defined(__WIN32__) || defined(WIN32)
#include <winsock2.h>
#include <windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <devpkey.h>
#include <winreg.h>
#include <utils/windows_helper.h>
#include <ddk/ndisguid.h>
#endif

#include "tun_device.h"

#include <utils/debug.h>
#include <threading/thread.h>

#if defined(__APPLE__)
#include "TargetConditionals.h"
#if !TARGET_OS_OSX
#define TUN_DEVICE_NOT_SUPPORTED
#endif
#elif ! (defined(__linux__) || defined(HAVE_NET_IF_TUN_H) || defined(WINTUN))
#define TUN_DEVICE_NOT_SUPPORTED
#endif

#ifdef TUN_DEVICE_NOT_SUPPORTED

tun_device_t *tun_device_create(const char *name_tmpl)
{
	DBG1(DBG_LIB, "TUN devices are not supported");
	return NULL;
}

#else /* TUN devices supported */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __WIN32__
#include "../utils/compat/windows.h"

#define IFNAMSIZ 256
#else
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#ifdef __APPLE__
#include <net/if_utun.h>
#include <netinet/in_var.h>
#include <sys/kern_control.h>
#elif defined(__linux__)
#include <linux/types.h>
#include <linux/if_tun.h>
#elif __FreeBSD__ >= 10
#include <net/if_tun.h>
#include <net/if_var.h>
#include <netinet/in_var.h>
#else
#include <net/if_tun.h>
#endif
#endif /* !__WIN32__ */

#define TUN_DEFAULT_MTU 1500

typedef struct private_tun_device_t private_tun_device_t;

struct private_tun_device_t {

	/**
	 * Public interface
	 */
	tun_device_t public;

#ifdef __WIN32__
        /**
         * The TUN device's HANDLE
         */
        HANDLE tun_handle;

        /**
         * The TUN device's rings
         */
        TUN_REGISTER_RINGS *rings;
#else
	/**
	 * The TUN device's file descriptor
	 */
	int tunfd;

	/**
	 * Socket used for ioctl() to set interface addr, ...
	 */
	int sock;
#endif /* !__WIN32__ */
	/**
	 * Name of the TUN device
	 */
	char if_name[IFNAMSIZ];

	/**
	 * The current MTU
	 */
	int mtu;

	/**
	 * Associated address
	 */
	host_t *address;

	/**
	 * Netmask for address
	 */
	uint8_t netmask;
};

#ifdef __WIN32__

METHOD(tun_device_t, set_mtu, bool,
	private_tun_device_t *this, int mtu)
{
	return TRUE;
}

METHOD(tun_device_t, get_mtu, int,
	private_tun_device_t *this)
{
        return TUN_MAX_IP_PACKET_SIZE;
}

static inline bool ring_over_capacity(TUN_RING *ring)
{
    return ((ring->Head >= TUN_RING_CAPACITY) || (ring->Tail >= TUN_RING_CAPACITY));
}

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

/* This is likely broken (!!!) */
static bool write_to_ring(TUN_RING *ring, chunk_t packet)
{
        /* Check if packet fits */
    TUN_PACKET *tun_packet;
    /* TODO: if ring is full or over capacity, wait until wintun driver sends event */
    if (ring_over_capacity(ring))
    {
        DBG1(DBG_LIB, "RING is over capacity!");
    }
    uint64_t aligned_packet_size = TUN_PACKET_ALIGN(packet.len);
    uint64_t buffer_space = TUN_WRAP_POSITION(((ring->Head - ring->Tail) - TUN_PACKET_ALIGNMENT), TUN_RING_CAPACITY);
    if (aligned_packet_size > buffer_space)
    {
        DBG1(DBG_LIB, "RING is full!");
    }
    
    /* copy packet size and data into ring */
    tun_packet = (TUN_PACKET *)&(ring->Data[ring->Tail]);
    tun_packet->Size = packet.len;
    memcpy(tun_packet->Data, packet.ptr, packet.len);
    
    /* move ring tail */
    ring->Tail = TUN_WRAP_POSITION((ring->Tail + aligned_packet_size), TUN_RING_CAPACITY);
    return TRUE;
}

static chunk_t *pop_from_ring(TUN_RING *ring)
{
        /* TODO: If ring is over capacity wait until event is sent */
        chunk_t *chunk_packet;
        /* Ring is empty if head == tail */
        if (ring_over_capacity(ring))
        {
            DBG0(DBG_LIB, "RING is over capacity!");
            return FALSE;
        }
        uint32_t length = TUN_WRAP_POSITION((ring->Tail - ring->Head),
            TUN_RING_SIZE(ring, TUN_RING_CAPACITY));
        if (length <sizeof(uint32_t))
        {
            DBG0(DBG_LIB, "RING contains incomplete packet header!");
            /* Need to restart the driver here */
        }
        TUN_PACKET *packet = (TUN_PACKET *)&(ring->Data[ring->Head]);
        if (packet->Size > TUN_MAX_IP_PACKET_SIZE)
        {
            DBG0(DBG_LIB, "RING contains packet larger than TUN_MAX_IP_PACKET_SIZE!");
        }

        size_t aligned_packet_size = TUN_PACKET_ALIGN(sizeof(uint32_t) + packet->Size);
        if (aligned_packet_size > length)
        {
            DBG0(DBG_LIB, "Incomplete packet in ring!");
        }

        chunk_packet = malloc(sizeof(chunk_t));
        chunk_packet->ptr = malloc(packet->Size);
        chunk_packet->len = packet->Size;
        memcpy(chunk_packet->ptr, packet->Data, chunk_packet->len);
        /* Do we need to memset here? */
        memset(packet->Data, 0, packet->Size);
        /* move ring head */
        ring->Head = TUN_WRAP_POSITION(ring->Head, aligned_packet_size);
        return chunk_packet;
}
#else
/**
 * FreeBSD 10 deprecated the SIOCSIFADDR etc. commands.
 */
#if __FreeBSD__ >= 10

static bool set_address_and_mask(struct in_aliasreq *ifra, host_t *addr,
								 uint8_t netmask)
{
	host_t *mask;

	memcpy(&ifra->ifra_addr, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));
	/* set the same address as destination address */
	memcpy(&ifra->ifra_dstaddr, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));

	mask = host_create_netmask(addr->get_family(addr), netmask);
	if (!mask)
	{
		DBG1(DBG_LIB, "invalid netmask: %d", netmask);
		return FALSE;
	}
	memcpy(&ifra->ifra_mask, mask->get_sockaddr(mask),
		   *mask->get_sockaddr_len(mask));
	mask->destroy(mask);
	return TRUE;
}

/**
 * Set the address using the more flexible SIOCAIFADDR/SIOCDIFADDR commands
 * on FreeBSD 10 an newer.
 */
static bool set_address_impl(private_tun_device_t *this, host_t *addr,
							 uint8_t netmask)
{
	struct in_aliasreq ifra;

	memset(&ifra, 0, sizeof(ifra));
	strncpy(ifra.ifra_name, this->if_name, IFNAMSIZ);

	if (this->address)
	{	/* remove the existing address first */
		if (!set_address_and_mask(&ifra, this->address, this->netmask))
		{
			return FALSE;
		}
		if (ioctl(this->sock, SIOCDIFADDR, &ifra) < 0)
		{
			DBG1(DBG_LIB, "failed to remove existing address on %s: %s",
				 this->if_name, strerror(errno));
			return FALSE;
		}
	}
	if (!set_address_and_mask(&ifra, addr, netmask))
	{
		return FALSE;
	}
	if (ioctl(this->sock, SIOCAIFADDR, &ifra) < 0)
	{
		DBG1(DBG_LIB, "failed to add address on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

#else /* __FreeBSD__ */

/**
 * Set the address using the classic SIOCSIFADDR etc. commands on other systems.
 */
static bool set_address_impl(private_tun_device_t *this, host_t *addr,
							 uint8_t netmask)
{
	struct ifreq ifr;
	host_t *mask;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	memcpy(&ifr.ifr_addr, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));

	if (ioctl(this->sock, SIOCSIFADDR, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set address on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
#ifdef __APPLE__
	if (ioctl(this->sock, SIOCSIFDSTADDR, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set dest address on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
#endif /* __APPLE__ */

	mask = host_create_netmask(addr->get_family(addr), netmask);
	if (!mask)
	{
		DBG1(DBG_LIB, "invalid netmask: %d", netmask);
		return FALSE;
	}
	memcpy(&ifr.ifr_addr, mask->get_sockaddr(mask),
		   *mask->get_sockaddr_len(mask));
	mask->destroy(mask);

	if (ioctl(this->sock, SIOCSIFNETMASK, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set netmask on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	return TRUE;

#endif /* __FreeBSD__ */
}

METHOD(tun_device_t, up, bool,
	private_tun_device_t *this)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);

	if (ioctl(this->sock, SIOCGIFFLAGS, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to get interface flags for %s: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}

	ifr.ifr_flags |= IFF_RUNNING | IFF_UP;

	if (ioctl(this->sock, SIOCSIFFLAGS, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set interface flags on %s: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}
	return TRUE;
}

METHOD(tun_device_t, set_mtu, bool,
	private_tun_device_t *this, int mtu)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	ifr.ifr_mtu = mtu;

	if (ioctl(this->sock, SIOCSIFMTU, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set MTU on %s: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}
	this->mtu = mtu;
	return TRUE;
}

METHOD(tun_device_t, get_mtu, int,
	private_tun_device_t *this)
{
	struct ifreq ifr;

	if (this->mtu > 0)
	{
		return this->mtu;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	this->mtu = TUN_DEFAULT_MTU;

	if (ioctl(this->sock, SIOCGIFMTU, &ifr) == 0)
	{
		this->mtu = ifr.ifr_mtu;
	}
	return this->mtu;
}


METHOD(tun_device_t, set_address, bool,
	private_tun_device_t *this, host_t *addr, uint8_t netmask)
{
	if (!set_address_impl(this, addr, netmask))
	{
		return FALSE;
	}
	DESTROY_IF(this->address);
	this->address = addr->clone(addr);
	this->netmask = netmask;
	return TRUE;
}

METHOD(tun_device_t, get_address, host_t*,
	private_tun_device_t *this, uint8_t *netmask)
{
	if (netmask && this->address)
	{
		*netmask = this->netmask;
	}
	return this->address;
}

METHOD(tun_device_t, get_name, char*,
	private_tun_device_t *this)
{
	return this->if_name;
}
#endif /* !__WIN32__ */
#ifdef __WIN32__
/* On WIN32 we return the handle of the read ring (kernel space -> user space) */
METHOD(tun_device_t, get_handle, HANDLE,
        private_tun_device_t *this)
{
        return this->rings->Send.TailMoved;
}

METHOD(tun_device_t, write_packet, bool,
        private_tun_device_t *this, chunk_t packet)
{
        write_to_ring(this->rings->Receive.Ring, packet);
        if (this->rings->Receive.Ring->Alertable)
        {
            SetEvent(this->rings->Receive.TailMoved);
        }
        return TRUE;
}
METHOD(tun_device_t, read_packet, bool, 
        private_tun_device_t *this, chunk_t *packet)
{
        chunk_t *next = pop_from_ring(this->rings->Send.Ring);
        if (!next)
        {
                this->rings->Send.Ring->Alertable = TRUE;
            next = pop_from_ring(this->rings->Send.Ring);
            if (!next)
            {
                WaitForSingleObject(this->rings->Send.TailMoved, INFINITE);
                this->rings->Send.Ring->Alertable = FALSE;
            }
            this->rings->Send.Ring->Alertable = FALSE,
            ResetEvent(this->rings->Send.TailMoved);
        }
        *packet = *next;
        return TRUE;
}

/* Bogus implementation because nobody should use this */
METHOD(tun_device_t, get_name, char*,
        private_tun_device_t *this)
{
        return this->if_name;
}

/* Bogus implementation because nobody should use this */
METHOD(tun_device_t, set_address, bool,
        private_tun_device_t *this,  host_t *addr, uint8_t netmask)
{
        return TRUE;
}
/* Bogus implementation because nobody should use this */
METHOD(tun_device_t, get_address, host_t*,
        private_tun_device_t *this, uint8_t *netmask)
{
    return NULL;
}
METHOD(tun_device_t, up, bool,
        private_tun_device_t *this)
{
    return TRUE;
}
#else
METHOD(tun_device_t, get_fd, int,
	private_tun_device_t *this)
{
	return this->tunfd;
}

METHOD(tun_device_t, write_packet, bool,
	private_tun_device_t *this, chunk_t packet)
{
        ssize_t s;
#ifdef __APPLE__
	/* UTUN's expect the packets to be prepended by a 32-bit protocol number
	 * instead of parsing the packet again, we assume IPv4 for now */
	uint32_t proto = htonl(AF_INET);
	packet = chunk_cata("cc", chunk_from_thing(proto), packet);
#endif
	s = write(this->tunfd, packet.ptr, packet.len);
	if (s < 0)
	{
		DBG1(DBG_LIB, "failed to write packet to TUN device %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	else if (s != packet.len)
	{
		return FALSE;
	}
	return TRUE;
}

METHOD(tun_device_t, read_packet, bool,
	private_tun_device_t *this, chunk_t *packet)
{
	chunk_t data;
	ssize_t len;
	bool old;

	data = chunk_alloca(get_mtu(this));

	old = thread_cancelability(TRUE);
	len = read(this->tunfd, data.ptr, data.len);
	thread_cancelability(old);
	if (len < 0)
	{
		DBG1(DBG_LIB, "reading from TUN device %s failed: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}
	data.len = len;
#ifdef __APPLE__
	/* UTUN's prepend packets with a 32-bit protocol number */
	data = chunk_skip(data, sizeof(uint32_t));
#endif
	*packet = chunk_clone(data);
	return TRUE;
}
#endif /* !__WIN32__ */

METHOD(tun_device_t, destroy, void,
	private_tun_device_t *this)
{
#ifdef __WIN32
        /* https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdiremovedevice */
        if (this->tun_handle)
        {
            ;
            /* dealloc tun device */
        }
#else
	if (this->tunfd > 0)
	{
		close(this->tunfd);
#ifdef __FreeBSD__
		/* tun(4) says the following: "These network interfaces persist until
		 * the if_tun.ko module is unloaded, or until removed with the
		 * ifconfig(8) command."  So simply closing the FD is not enough. */
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
		if (ioctl(this->sock, SIOCIFDESTROY, &ifr) < 0)
		{
			DBG1(DBG_LIB, "failed to destroy %s: %s", this->if_name,
				 strerror(errno));
		}
#endif /* __FreeBSD__ */
	}
	if (this->sock > 0)
	{
		close(this->sock);
	}
#endif /* !__WIN32__ */
	DESTROY_IF(this->address);
	free(this);
}

#ifdef __WIN32__
/**
 * Destroy the tun device
 */
static bool destroy_wintun(char *GUID)
{
    ;
    /* Get all present interfaces */
}

static char *windows_setupapi_get_friendly_name(char *buffer, size_t buf_len, HDEVINFO dev_info_set, SP_DEVINFO_DATA *dev_info_data)
{
	memset(buffer, 0, sizeof(buffer));
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

/**
 * Create the tun device and configure it as stored in the registry.
 * @param guid			GUID    GUID that the new interface should use.
 *					Can be NULL to make the system choose one at random.
 * @return bool			Whether creating failed or succeeded.
 */
bool create_wintun(char *guid)
{
	/* Reimplementation of CreateInterface from wireguard */
	char className[MAX_CLASS_NAME_LEN], buf[512], interface_name[512];
	uint64_t index = 0, driverVersion = 0;
	char *property_buffer = NULL, error_buf[512];
	DWORD property_buffer_length = 0, required_length = 0,
            reg_value_type, error;
	FILETIME driver_date;
	DWORDLONG driver_version;
	bool return_code = FALSE;
	HKEY drv_reg_key;
	/* Timeout of 5000 ms for registry operations */
	size_t registry_timeout = 5000, buffer_length;
	/* Create an empty device info set for network adapter device class. */
	SP_DEVINFO_DATA dev_info_data;
	SP_DRVINFO_DATA_A drv_info_data;
	SP_DEVINSTALL_PARAMS_A dev_install_params;
	SP_DRVINFO_DETAIL_DATA_A drv_info_detail_data;
        SP_DEVICE_INTERFACE_DATA dev_interface_data;
	/* is this optimizable? */
	drv_info_data.cbSize = sizeof(SP_DRVINFO_DATA_A);
	dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
	dev_install_params.cbSize = sizeof(SP_DEVINSTALL_PARAMS_A);
	HDEVINFO dev_info_set = SetupDiCreateDeviceInfoListExA(
		&GUID_DEVCLASS_NET,
		NULL,
		NULL,
		NULL
        );
        DEVPROPKEY propkey;
        /* wait 50 ms */
        struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 50000000,
        };
	
	if (!dev_info_set)
	{
		DBG1(DBG_LIB,
			"Failed to create DeviceInfoList(SetupDiCreateDeviceInfoListExA): %s",
			dlerror_mt(buf, sizeof(buf)));
			return FALSE;
	}

	if(!SetupDiClassNameFromGuidExA(
		&GUID_DEVCLASS_NET,
		className,
		sizeof(className),
		&required_length,
		NULL,
		NULL
	))
	{
		DBG1(DBG_LIB, "Failed to translate GUID to class name (SetupDiClassNameFromGuidExA): %s",
			dlerror_mt(buf, sizeof(buf)));
		return FALSE;
	}

	if (required_length > sizeof(className))
	{
		property_buffer = calloc(required_length, 1);
		property_buffer_length = required_length;
		if(!SetupDiClassNameFromGuidExA(
			&GUID_DEVCLASS_NET,
			property_buffer,
			property_buffer_length,
			&required_length,
			NULL,
			NULL
		))
		{
			// log error and return
		}
	}

	/* property_buffer now holds class name */
	if (!SetupDiCreateDeviceInfo(
		dev_info_set,
		property_buffer,
		&GUID_DEVCLASS_NET,
		STRONGSWAN_WINTUN_INTERFACE_NAME,
		NULL,
		DICD_GENERATE_ID,
		&dev_info_data))
	{
		// log error, cleanup and return 
	}


	// create device
	// Set quiet install setQuietInstall
	if(!SetupDiGetDeviceInstallParamsA(dev_info_set,&dev_info_data, &dev_install_params))
	{
		DBG1(DBG_LIB, "Failed to create wintun interface at (SetupDiGetDeviceInstallParamsA): %s", dlerror_mt(buf, sizeof(buf)));
		goto delete_driver_info_list;
	}

	dev_install_params.Flags |= DI_QUIETINSTALL;

	if(!SetupDiSetDeviceInstallParamsA(dev_info_set, &dev_info_data, &dev_install_params))
	{
		// log error, cleanup and return	
	}

	// Set a device information element as the selected member of a device information set. SetupDiSetSelectedDevice
	if(!SetupDiSetSelectedDevice(dev_info_set, &dev_info_data))
	{
		// log error, cleanup and return	
	}

	// Set Plug&Play device hardware ID property. SetupDiSetDeviceRegistryProperty

	if(!SetupDiSetDeviceRegistryPropertyA(
		dev_info_set,
		&dev_info_data,
		SPDRP_HARDWAREID,
		WINTUN_COMPONENT_ID,
		sizeof(WINTUN_COMPONENT_ID)))
	{
		// log error, cleanup and return	
	}

	if(!SetupDiBuildDriverInfoList(dev_info_set, &dev_info_data, SPDIT_COMPATDRIVER))
	{
		// log error, cleanup and return
	}
	// Following this, DestroyDriverInfoList has to be called, too

	// loop over members of dev_info_data using EnumDriverInfo and index
	// loop over devices, search for newest driver version

	while(TRUE)
	{
		if(!SetupDiEnumDriverInfo(
			dev_info_set,
			&dev_info_data,
			SPDIT_COMPATDRIVER,
			index,
			&drv_info_data))
		{
			error = GetLastError();
			if (error == ERROR_NO_MORE_ITEMS)
			{
				// break and go on
				break;
			}
			// Skip broken driver records
			continue;
		}
		// DriverInfoDetail is SetupDiGetDriverInfoDetailA() that returns a struct of type SP_DRVINFO_DETAIL_DATA_A
		if(!SetupDiGetDriverInfoDetailA(
			dev_info_set,
			&dev_info_data,
			&drv_info_data,
			&drv_info_detail_data,
			sizeof(drv_info_detail_data),
			&required_length
			))
		{
			error = GetLastError();
			if (error == ERROR_INSUFFICIENT_BUFFER)
			{
				// allocate memory
				property_buffer = realloc(property_buffer, required_length);
				property_buffer_length = required_length;
				if(!SetupDiGetDriverInfoDetailA(
					dev_info_set,
					&dev_info_data,
					&drv_info_data,
					&drv_info_detail_data,
					sizeof(drv_info_detail_data),
					&required_length
				))
				{
					error = GetLastError();
					if (error)
					{
						// previous returned length was bogus, something
						// is fishy. Log error message and skip item.
						DBG1(DBG_LIB, "Previous required length was bogus. New error is %s", dlerror_mt(buf, sizeof(buf)));
						continue;
					}
				}
			}
			// other error occured. Log error and skip item.
			DBG1(DBG_LIB, "A different error occured: %s", dlerror_mt(buf, sizeof(buf)));
			continue;
		}
		// If the device does have a hardware ID, check it.
		if (drv_info_detail_data.CompatIDsOffset > 1)
		{
			if (strcaseeq(drv_info_detail_data.HardwareID, WINTUN_COMPONENT_ID)) {
				// hardware ID doesn't match
				// check compatible hardware IDs
				if(drv_info_detail_data.CompatIDsLength > 0 &&
					!find_matching_hardwareid(drv_info_detail_data.HardwareID, WINTUN_COMPONENT_ID))
				{
					DBG2(DBG_LIB, "ID %s is not in compatible hardware IDs.", WINTUN_COMPONENT_ID);
					continue;
				}
			}
		}
		// Iterate over HardwareID array in drv_info_detail_data
		if (drv_info_detail_data.CompatIDsLength > 0)
		{
			if(!find_matching_hardwareid(drv_info_detail_data.HardwareID, WINTUN_COMPONENT_ID))
			{
				DBG2(DBG_LIB, "ID %s is not in compatible hardware IDs.", WINTUN_COMPONENT_ID);
				continue;
			}

		}

		// device is compatible, store newest driver version and date
		if(CompareFileTime(&drv_info_data.DriverDate, &driver_date) == 1)
		{
			if(!SetupDiSetSelectedDriverA(dev_info_set, &dev_info_data, &drv_info_data))
			{
				DBG1(DBG_LIB, "Failed to set driver of device %s for new wintun device %s",
					dlerror_mt(buf, sizeof(buf)),
					windows_setupapi_get_friendly_name(buf, sizeof(buf), dev_info_set, &dev_info_data));
				continue;
			}
			driver_version = drv_info_data.DriverVersion;
			driver_date = drv_info_data.DriverDate;
		}
		index++;
	if(driver_version == 0)
	{
		DBG1(DBG_LIB, "No driver installed for device %s", dlerror_mt(buf, sizeof(buf)));
		goto delete_driver_info_list;
	}

	/* Call appropriate class installer */
	if (!SetupDiCallClassInstaller(
		DIF_REGISTERDEVICE,
		dev_info_set,
		&dev_info_data
	))
	{
		DBG1(DBG_LIB, "SetupDiCallClassInstaller(DIF_REGISTERDEVICE) failed: %s", dlerror_mt(buf, sizeof(buf)));
		goto uninstall_device;
	}

	for (int i=0;i<200;i++)
	{
                drv_reg_key = SetupDiOpenDevRegKey(dev_info_set, &dev_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_NOTIFY);
                if (drv_reg_key)
                {
                        /* Got registry key */
                        break;
                }
                /* Make sure the thread sleeps at least 50 ms */
                while(!nanosleep(&ts, &ts))
                {}
	}
	guid2string(property_buffer, property_buffer_length, (GUID *) &GUID_WINTUN_STRONGSWAN);
	char buf[512];
	snprintf(buf, sizeof(buf), "{%s}", property_buffer);
	if (!RegSetKeyValueA(drv_reg_key, NULL, "NetSetupAnticipatedInstanceId", REG_SZ, buf, strlen(buf)))
	{
		DBG1(DBG_LIB, "Failed to set regkey NetSetupAnticipatedInstanceId (RegSetKeyValueA): %s", dlerror_mt(buf, sizeof(buf)));
		goto close_drv_reg_key;
	}
	SetupDiCallClassInstaller(
		DIF_INSTALLINTERFACES,
		dev_info_set,
		&dev_info_data
	);

	if (!SetupDiCallClassInstaller(
		DIF_INSTALLDEVICE,
		dev_info_set,
		&dev_info_data
		))
	{
		DBG1(DBG_LIB, "Failed to install device (SetupDicallInstaller(DIF_INSTALLDEVICE)): %s", dlerror_mt(buf, sizeof(buf)));
		goto close_drv_reg_key;
	}

	if (!SetupDiGetDeviceInstallParamsA(
		dev_info_set,
		&dev_info_data,
		&dev_install_params
		))
	{
		DBG1(DBG_LIB, "Failed to get install params (SetupDiGetDeviceInstallParamsA): %s", dlerror_mt(buf, sizeof(buf)));
		goto close_drv_reg_key;
	}
	
	/* if (dev_install_params.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART))
	{

	} */

	if (!SetupDiSetDeviceRegistryPropertyA(
		dev_info_set,
		&dev_info_data,
		SPDRP_DEVICEDESC,
		WINTUN_COMPONENT_ID,
		sizeof(WINTUN_COMPONENT_ID
	)))
	{
		DBG1(DBG_LIB, "Failed to get device description (SetupDiSetDeviceRegistryPropertyA(SPDRP_DEVICEDESC)) failed: %s", dlerror_mt(buf, sizeof(buf)));
		goto close_drv_reg_key;
	}

	if (!registry_wait_get_value(drv_reg_key, property_buffer, &property_buffer_length, "NetCfgInstanceId", &reg_value_type, registry_timeout))
	{
		DBG1(DBG_LIB, "Failed to retrieve NetCfgInstanceId key. Aborting tun device installation.");
		goto close_drv_reg_key;
	}
	if (!(reg_value_type &= (REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ)))
	{
		DBG1(DBG_LIB, "Type of NetCfgInstanceId is not REG_SZ, REG_EXPAND_SZ or REG_MULTI_SZ (Meaning it is not a string). Aborting tun device install.");
		goto close_drv_reg_key;
	}
	/* Expand string */

	char *new_buf = windows_expand_string(property_buffer, &property_buffer_length, &buffer_length);

	if (!registry_wait_get_value(drv_reg_key, property_buffer, &property_buffer_length, "NetLuidIndex", &reg_value_type, registry_timeout))
	{
		DBG1(DBG_LIB, "Failed to retrieve NetLuidIndex key. Aborting tun device installation.");
		goto close_drv_reg_key;
	}
	if (reg_value_type != REG_DWORD)
	{
		DBG1(DBG_LIB, "Type of NetLuidIndex is not REG_DWORD. Aborting tun device installation.");
		goto close_drv_reg_key;
	}

	if (!registry_wait_get_value(drv_reg_key, property_buffer, &property_buffer_length, "*IfType", &reg_value_type, registry_timeout))
	{
		DBG1(DBG_LIB, "Failed to retrieve *IfType key. Aborting tun device installation.");
		goto close_drv_reg_key;
	}
	if (reg_value_type != REG_DWORD)
	{
		DBG1(DBG_LIB, "Type of *IfType is not REG_DWORD. Aborting tun device installation.");
		goto close_drv_reg_key;
	}

	// SetupDiCallClassInstaller

	// after this, when exiting, we need to run all the functions that are deferred in the Gocode

	// Register device co-installers if any. (Ignore errors)

	// devInfo.OpenDevRegKey

	// SetupDiOpenDevRegKey

	// netDevRegKey.SetStringValue("NetSetupAnticipatedInstanceId

	// Install interfaces if any. (Ignore errors)

	// SetupDiCallClassInstaller

	// checkReboot

	// devInfo.SetDeviceRegistryPropertyString

	// registryEx.GetStringValueWait(netDevRegKey, "NetCfgInstanceId",

	// registryEx.GetIntegerValueWait(netDevRegKey, "NetLuidIndex",

	// registryEx.GetIntegerValueWait(netDevRegKey, "*IfType",

	// Wait for TCP/IP adapter registry key to emerge and populate.

	// OpenKeyWait

	// GetStringValueWait

	// tcpipInterfaceRegKeyName

	// OpenKeyWait
	// EnableDeadGWDetect

close_drv_reg_key :
	RegCloseKey(drv_reg_key);

delete_driver_info_list : ;
	if (!return_code)
	{
		/* RemoveDeviceParams yade yade yada */
uninstall_device : ;
		/* SP_CLASSINSTALL_HEADER class_install_header = {
			.cbSize = sizeof(SP_CLASSINSTALL_HEADER),
			.InstallFunction = DIF_REMOVE
		};
		*/
		SP_REMOVEDEVICE_PARAMS remove_device_params = {
			.ClassInstallHeader = {
				.cbSize = sizeof(SP_CLASSINSTALL_HEADER),
				.InstallFunction = DIF_REMOVE
			},
			.Scope = DI_REMOVEDEVICE_GLOBAL,
			.HwProfile = 0
		};
		if (!SetupDiCallClassInstaller(DIF_REMOVE,
			dev_info_set,
			&dev_info_data))
		{
			DBG1(DBG_LIB, "Failed to remove device (SetupDiCallClassInstaller): %s", dlerror_mt(buf, sizeof(buf)));
		}
	}
	if (!SetupDiDestroyDriverInfoList(dev_info_set, &dev_info_data, SPDIT_COMPATDRIVER))
	{
		DBG1(DBG_LIB, "Failed to destroy driver info list (SetupDiDestroyDriverInfoList): %s", dlerror_mt(buf, sizeof(buf)));
	}
delete_device_info_list :
	if (!SetupDiDestroyDeviceInfoList(dev_info_set))
	{
		DBG1(DBG_LIB, "Failed to delete device info set (SetupDiDestroyDeviceInfoList): %s", dlerror_mt(buf, sizeof(buf)));
	}
        if(new_buf)
        {
            free(new_buf);
        }
    return return_code;
}

/**
 * Implements func (pool Pool) GetInterface(ifname string) (*Interface, error)
 * Get a wintun interface handle with that ifname.
 * If it already exists, it is deleted first and a new one is created.
 * This guarantees that the device is always configured correctly.
 * @param		ifname 		desired name of the interface
 * @return 					HANDLE to the wintun device
 */
bool wireguard_get_interface()
{
        GUID guid;
	SP_DEVICE_INTERFACE_DATA dev_interface_data;
        SP_DEVINFO_DATA dev_info_data;
	HDEVINFO dev_info_set;
	dev_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
	char *property_buffer = NULL, buf[512];
	DWORD error = 0;
	uint32_t ctr = 0;
	size_t property_buffer_length = 0, required_buffer_size = 0;
	/* Initialise list */
	dev_info_set = SetupDiCreateDeviceInfoListExA(
		&GUID_DEVCLASS_NET,
		NULL,
		NULL,
		NULL
		);
	if (dev_info_set == INVALID_HANDLE_VALUE)
	{
		DBG1(DBG_LIB, "Failed to create device info list (SetupDiCreateDeviceInfoListExA): %s", dlerror_mt(buf, sizeof(buf)));
		return FALSE;
	}
	/* Get all currently existing network interfaces */
	dev_info_set = SetupDiGetClassDevsExA(
		&GUID_DEVCLASS_NET,
		"",
		NULL,
		DIGCF_PRESENT,
		dev_info_set,
		"",
		NULL
		);
	
	/* Abort if getting list of existing network interfaces failed */
	if (!dev_info_set || dev_info_set == INVALID_HANDLE_VALUE)
	{
		DBG1(DBG_LIB, "SetupDiGetClassDevsExA() failed to enumerate network devices: %s", dlerror_mt(buf, sizeof(buf)));
		goto delete_device_info_list;
		return FALSE;
	}
	/* enumerate the devices in the collection*/
	/* Check if hardware ID is Wintun */
	while(TRUE)
	{
		DBG2(DBG_LIB, "Looking at %s",
                        windows_setupapi_get_friendly_name(buf, sizeof(buf), dev_info_set, &dev_info_data));
		if (!SetupDiEnumDeviceInfo(dev_info_set, ctr++, &dev_info_data))
		{
			DBG2(DBG_LIB, "Encountered error in processing of list: %s", dlerror_mt(buf, sizeof(buf)));
			if (error == ERROR_NO_MORE_ITEMS)
			{
				DBG2(DBG_LIB, "Reached end of network interface list.");
				break;
			}
			/* Translate error into text and log it. Use FormatMessage */
			/* Continue enumerating other network interfaces */
			continue;
		}
		/* Get information about this particular network interface */
		/* Get needed length to store property */
		if (!SetupDiGetDeviceRegistryPropertyA(
			dev_info_set,
			&dev_info_data,
			SPDRP_ADDRESS,
			NULL,
			NULL,
			0,
			(DWORD *)&required_buffer_size
			))
		{
			DWORD error = GetLastError();
			/* Request failed, log error and continue */
			if(error == ERROR_INVALID_DATA)
			{
                            DBG1(DBG_LIB,
                                    "Network interface %s doesn't have a hardware address. Skipping.",
                                    windows_setupapi_get_friendly_name(buf, sizeof(buf), dev_info_set, &dev_info_data));
			}
			continue;
		}
		if (property_buffer_length < required_buffer_size)
		{
			property_buffer = realloc(property_buffer, required_buffer_size);
			property_buffer_length = required_buffer_size;
		}
		if (!SetupDiGetDeviceRegistryPropertyA(
			dev_info_set,
			&dev_info_data,
			SPDRP_ADDRESS,
                        NULL,
			property_buffer,
			required_buffer_size,
			NULL
			))
		{
			/* Request failed, log error and continue */
			DBG1(DBG_LIB, "Failed to get hardwareID for device %s: %s",
                                windows_setupapi_get_friendly_name(buf, sizeof(buf), dev_info_set, &dev_info_data),
                                dlerror_mt(error_buf, sizeof(error_buf)));
			continue;
		}
		/* Check hardware id (must be wintun) */
		if (!strcaseeq(property_buffer,  "Wintun"))
		{
			/* Not a wintun type device */
			continue;
		}
		/* It's a wintun type device, check if its name (case insensitive) is the same as ifname */
		HKEY key = SetupDiOpenDevRegKey(dev_info_set, &dev_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_QUERY_VALUE);
		/* return nil, fmt.Errorf("Device-specific registry key open failed: %v", err) */
		error = RegQueryValueEx(key, "NetCfgInstanceId", NULL, NULL, property_buffer, (DWORD *) &property_buffer_length);
		if (error != ERROR_SUCCESS)
		{
			if (error == ERROR_MORE_DATA)
			{
				property_buffer = realloc(property_buffer, property_buffer_length);
				error = RegQueryValueEx(key, "NetCfgInstanceId", NULL, NULL, property_buffer, (DWORD *) &property_buffer_length);
				if (error)
				{
					dlerror_mt(error_buf, sizeof(error_buf));
					DBG1(DBG_LIB,
                                                "Failed to get NetCfgInstanceId for interface %s: %s",
						windows_setupapi_get_friendly_name(buf, sizeof(buf), dev_info_set, &dev_info_data),
						error_buf);
					continue;
				}
			} else {
				DBG1(DBG_LIB,
                                        "Failed to get NetCfgInstanceId for interface %s: %s",
					windows_setupapi_get_friendly_name(buf, sizeof(buf), dev_info_set, &dev_info_data),
					dlerror_mt(error_buf, sizeof(error_buf)));
				continue;
			}
		}
		/* Convert NetCfgInstanceId to GUID */
		if(!guidfromstring(&guid, property_buffer))
		{
			dlerror_mt(error_buf, sizeof(error_buf));
			DBG1(DBG_LIB, "Failed to convert NetCfgInstanceId %s into GUID: %s",
				property_buffer, dlerror_mt(buf, sizeof(buf)));
			continue;
		}
		/* Check if GUID is the same */
		if (!memcmp(property_buffer, &GUID_WINTUN_STRONGSWAN, min(sizeof(GUID_WINTUN_STRONGSWAN), property_buffer_length)))
		{
			/* Is not the guid */
			continue;
		}
		/* It's the strongSwan VPN adapter. We delete it and recreate it to make sure it works. */
		/* TODO: Actually integrate that */

	}

delete_device_info_list:
        if(property_buffer)
        {
            free(property_buffer);
        }
	if (!SetupDiDestroyDeviceInfoList(dev_info_set))
	{
		DBG1(DBG_LIB, "Failed to destroy device info set (SetupDiDestroyDeviceInfoList): %s", dlerror_mt(buf, sizeof(buf)));
		return FALSE;
	}
	return TRUE;
}


char *search_interfaces(char *GUID)
{
        char *interfaces = NULL;
        DWORD required_bytes = 0;
        CONFIGRET ret;
        for(int tries=0;tries<50;tries++)
        {
            if (interfaces)
            {
                free(interfaces);
                interfaces = NULL;
            }
            while(TRUE)
            if (CM_Get_Device_Interface_List_Size(&required_bytes, (LPGUID)&GUID_DEVINTERFACE_NET,
                GUID, CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS)
                return NULL;
            interfaces = realloc(interfaces, required_bytes);
            if (!interfaces)
                return NULL;
            ret = CM_Get_Device_Interface_List((LPGUID)&GUID_DEVINTERFACE_NET, GUID,
                            interfaces, required_bytes, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
            if (ret == CR_SUCCESS)
                break;
            if (ret != CR_BUFFER_SMALL)
            {
                free(interfaces);
                return NULL;
            }
        }
        return interfaces;
}

#endif  /* WIN32 */

bool init_tun(private_tun_device_t *this, const char *name_tmpl)
{
#ifdef WIN32
        char buf[512];
        /* WINTUN driver specific stuff */
        /* Check if the TUN device already exists */

        /* If the TUN device already exists, delete it */
        /* If the TUN device doesn't exist, create it */
        char *InterfaceList = search_interfaces(PNP_INSTANCE_ID);
        bool ret;
        if (InterfaceList)
        {
            destroy_wintun(PNP_INSTANCE_ID);
        }
        if (!create_wintun(PNP_INSTANCE_ID))
        {

        }
        //if (!config_wintun(PNP_INSTANCE_ID)){}
        /* Open the handle by using the InterfaceList */
        this->tun_handle = CreateFile(InterfaceList, GENERIC_READ | GENERIC_WRITE,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         NULL, OPEN_EXISTING, 0, NULL);
        if(!this->tun_handle)
        {
        	/* Failed to open file, log error */
        	DBG1(DBG_LIB, "Failed to open tun file handle: %s", dlerror_mt(buf, sizeof(buf)));

        }
        /* Create structs for rings and the rings themselves */
        this->rings = calloc(sizeof(TUN_REGISTER_RINGS), 1);
        this->rings->Send.Ring = calloc(sizeof(TUN_RING), 1);
        this->rings->Receive.Ring = calloc(sizeof(TUN_RING), 1);
        
        /* this->rings->Receive.Ring = malloc(TUN_RING_SIZE(this->rings->Receive, TUN_RING_CAPACITY));
        this->rings->Send.Ring = malloc(TUN_RING_SIZE(this->rings->Send, TUN_RING_CAPACITY));
        */
        /* Tell driver about the rings */
        DeviceIoControl(this->tun_handle,
            TUN_IOCTL_REGISTER_RINGS,
            &this->rings->Receive,
            TUN_RING_SIZE(this->rings->Receive, TUN_RING_CAPACITY),
            &this->rings->Send,
            TUN_RING_SIZE(this->rings->Send, TUN_RING_CAPACITY),
            NULL,
            NULL
        );
        /* We're done now */
#elif defined(__APPLE__)

	struct ctl_info info;
	struct sockaddr_ctl addr;
	socklen_t size = IFNAMSIZ;

	memset(&info, 0, sizeof(info));
	memset(&addr, 0, sizeof(addr));

	this->tunfd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (this->tunfd < 0)
	{
		DBG1(DBG_LIB, "failed to open tundevice PF_SYSTEM socket: %s",
			 strerror(errno));
		return FALSE;
	}

	/* get a control identifier for the utun kernel extension */
	strncpy(info.ctl_name, UTUN_CONTROL_NAME, strlen(UTUN_CONTROL_NAME));
	if (ioctl(this->tunfd, CTLIOCGINFO, &info) < 0)
	{
		DBG1(DBG_LIB, "failed to ioctl tundevice: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}

	addr.sc_id = info.ctl_id;
	addr.sc_len = sizeof(addr);
	addr.sc_family = AF_SYSTEM;
	addr.ss_sysaddr = AF_SYS_CONTROL;
	/* allocate identifier dynamically */
	addr.sc_unit = 0;

	if (connect(this->tunfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_LIB, "failed to connect tundevice: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}
	if (getsockopt(this->tunfd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
				   this->if_name, &size) < 0)
	{
		DBG1(DBG_LIB, "getting tundevice name failed: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}
	return TRUE;

#elif defined(IFF_TUN)

	struct ifreq ifr;

	strncpy(this->if_name, name_tmpl ?: "tun%d", IFNAMSIZ);
	this->if_name[IFNAMSIZ-1] = '\0';

	this->tunfd = open("/dev/net/tun", O_RDWR);
	if (this->tunfd < 0)
	{
		DBG1(DBG_LIB, "failed to open /dev/net/tun: %s", strerror(errno));
		return FALSE;
	}

	memset(&ifr, 0, sizeof(ifr));

	/* TUN device, no packet info */
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	if (ioctl(this->tunfd, TUNSETIFF, (void*)&ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to configure TUN device: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}
	strncpy(this->if_name, ifr.ifr_name, IFNAMSIZ);
	return TRUE;

#elif defined(__FreeBSD__)

	if (name_tmpl)
	{
		DBG1(DBG_LIB, "arbitrary naming of TUN devices is not supported");
	}

	this->tunfd = open("/dev/tun", O_RDWR);
	if (this->tunfd < 0)
	{
		DBG1(DBG_LIB, "failed to open /dev/tun: %s", strerror(errno));
		return FALSE;
	}
	fdevname_r(this->tunfd, this->if_name, IFNAMSIZ);
	return TRUE;

#else /* !__FreeBSD__ */

	/* this might work on Linux with older TUN driver versions (no IFF_TUN) */
	char devname[IFNAMSIZ];
	/* the same process is allowed to open a device again, but that's not what
	 * we want (unless we previously closed a device, which we don't know at
	 * this point).  therefore, this counter is static so we don't accidentally
	 * open a device twice */
	static int i = -1;

	if (name_tmpl)
	{
		DBG1(DBG_LIB, "arbitrary naming of TUN devices is not supported");
	}

	for (; ++i < 256; )
	{
		snprintf(devname, IFNAMSIZ, "/dev/tun%d", i);
		this->tunfd = open(devname, O_RDWR);
		if (this->tunfd > 0)
		{	/* for ioctl(2) calls only the interface name is used */
			snprintf(this->if_name, IFNAMSIZ, "tun%d", i);
			break;
		}
		DBG1(DBG_LIB, "failed to open %s: %s", this->if_name, strerror(errno));
	}
	return this->tunfd > 0;

#endif /* !WIN32*/
}

/*
 * Described in header
 */
tun_device_t *tun_device_create(const char *name_tmpl)
{
	private_tun_device_t *this;

	INIT(this,
		.public = {
			.read_packet = _read_packet,
			.write_packet = _write_packet,
			.get_mtu = _get_mtu,
			.set_mtu = _set_mtu,
			.get_name = _get_name,
#ifdef WIN32
                        .get_handle = _get_handle,
#else
			.get_fd = _get_fd,
#endif /* !WIN32 */
			.set_address = _set_address,
			.get_address = _get_address,
			.up = _up,
			.destroy = _destroy,
		},
#ifdef WIN32
                .tun_handle = NULL,
#else
		.tunfd = -1,
		.sock = -1,
#endif
	);

	if (!init_tun(this, name_tmpl))
	{
		free(this);
		return NULL;
	}
	DBG1(DBG_LIB, "created TUN device: %s", this->if_name);
#ifdef WIN32
#else
	this->sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (this->sock < 0)
	{
		DBG1(DBG_LIB, "failed to open socket to configure TUN device");
		destroy(this);
		return NULL;
	}
#endif /* !WIN32 */
	return &this->public;
}}

#endif /* TUN devices supported */
