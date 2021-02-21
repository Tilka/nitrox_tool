#!/usr/bin/env python3

import struct
import sys
import hashlib

for path in sys.argv[1:]:
	print(f'Scanning {path}')
	d = open(path, 'rb').read()
	i = 0
	j = None
	threshold = 100
	while i + 4 < len(d):
		if j is None:
			if i + 16 >= len(d):
				break
			w = struct.unpack('>IIII', d[i:i+16])
			if (w[0] >> 17 == 0 and
			    w[1] >> 17 == 1 and
			    w[2] >> 17 == 2 and
			    w[3] >> 17 == 3):
				#print(f'Maybe at {i}')
				j = i
				i += 4
			else:
				i += 1
		else:
			word = struct.unpack('>I', d[i:i+4])[0]
			offset = word >> 17
			#parity = (word >> 16) & 1
			#payload = word & 0xffff
			if offset == (i - j) // 4:
				i += 4
			else:
				if i - j > threshold:
					print(f'Found microcode at {hex(j)} of length {i - j}')
					code = d[j:i]
					name = hashlib.md5(code).hexdigest()
					open(f'/tmp/code_{name}.bin', 'wb+').write(code)
				else:
					pass #print(f'Nope, too small ({i - j})')
				i += 1
				j = None
