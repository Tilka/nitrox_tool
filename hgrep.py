#!/usr/bin/env python3

import sys
import binascii

pattern = binascii.unhexlify(sys.argv[1].replace(' ', ''))
for path in sys.argv[2:]:
	data = open(path, 'rb').read()
	if data.find(pattern) != -1:
		print(path, 'matches')
