#!/usr/bin/env python3

def pci_addr(bus, dev, fn, reg):
	return (0x80000000 | (bus << 16) | ((dev & 0x1F) << 11) | ((fn & 0x7) << 8) | (reg & 0xFF))

def decode(x):
	return {
		'bus': (x >> 16) & 0x7FFF,
		'dev': (x >> 11) & 0x1F,
		'fun': (x >> 8) & 0x7,
		'reg': x & 0xFF
	}

import sys
for arg in sys.argv[1:]:
	print(decode(eval(arg)))
