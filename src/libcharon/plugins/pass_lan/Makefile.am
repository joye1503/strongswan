AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pass_lan.la
else
plugin_LTLIBRARIES = libstrongswan-pass_lan.la
endif

libstrongswan_pass_lan_la_SOURCES = \
	pass_lan_plugin.h pass_lan_plugin.c \
	pass_lan_listener.h pass_lan_listener.c

libstrongswan_pass_lan_la_LDFLAGS = -module -avoid-version
