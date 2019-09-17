#!/bin/bash
	CC=arm-linux-gcc \
	LIBS="-lssl -lglib-2.0 -lgio-2.0 -lcrypto -lgobject-2.0 -lgmodule-2.0 -lpcre -lz -lffi -lcurl -lcares" \
	LDFLAGS="-L/home/cbx/glib-lib/lib -L/home/cbx/tvlibs/pcre-lib -L/home/cbx/tvlibs/libffi-lib -L/home/cbx/mt5658m/android/lib" \
	GLIB_LIBS=-L/home/cbx/glib-lib/lib \
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/cbx/tvlibs/libffi-lib \
	GLIB_CFLAGS="-I/home/cbx/glib-lib/include/glib-2.0 -I/home/cbx/glib-lib/lib/glib-2.0/include -I/home/cbx/mt5658m/android/include/" \
	./configure --prefix=/home/cbx/libnice-lib \
       --host=armv7a-mediatek482_001_neon-linux-gnueabi \
       --with-openssl=/home/cbx/mt5658m/android/

