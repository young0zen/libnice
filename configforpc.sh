#!/bin/bash
        LIBS=-lcurl \
        LDFLAGS=-L/usr/local/lib \
	CFLAGS=-I/usr/local/include/ \
        ./configure --prefix=/home/cbx/libnice-lib \
