#!/usr/bin/env python3

import argparse
import binascii
import hashlib
import struct

def read4(d):
	return struct.unpack('>I', d[0:4])[0]

def round16(x):
	return (x + 15) & ~15

def hexdump(data, offset=0):
	size = len(data)
	for i in range(0, size, 16):
		print(f'{offset+i:04X}:', end='')
		for j in range(i, i + 16):
			if j % 16 == 8:
				print(' ', end='')
			if j < size:
				print(f' {data[j]:02X}', end='')
			else:
				print('  ', end='')
		print('  ', end='')
		for j in range(i, min(i + 16, size)):
			if j % 16 == 8:
				print(' ', end='')
			n = data[j]
			c = chr(n) if n > 32 and n < 127 else '.'
			print(c, end='')
		print()

def handle_file(path, args):
	d = open(path, 'rb').read()
	if args.raw:
		dump_microcode(args, d)
		return
	mc_type = d[0]
	version = d[1:0x20]
	code_len = read4(d[0x20:])
	data_len = read4(d[0x24:])
	sram_addr = read4(d[0x2C:])
	if version.startswith(b'CNN5x'):
		code_len *= 2
	else:
		code_len *= 4

	code_start = 0x30
	code_end = code_start + code_len
	data_start = round16(code_end)
	data_end = data_start + data_len
	sig_start = round16(data_end)
	sig_end = sig_start + 256

	code = d[code_start:code_end]
	data = d[data_start:data_end]
	signature = d[sig_start:sig_end]

	if args.mystery:
		print('mystery number:', binascii.hexlify(data[:8]).decode('ascii'), path)
		return
	dump_microcode(args, code, data, mc_type, version, sram_addr, sig_end)

def compute_parity(n):
	p = 0
	while n:
		p ^= n & 1
		n >>= 1
	return p

def dump_microcode(args, code, data=b'', mc_type=0, version=b'', sram_addr=0, sig_end=0):
	if args.verbose == 0 or args.verbose > 1:
		print(path)
		print('microcode:', mc_type)
		print('version:', version[:version.find(0)])
		print('code size:', hex(len(code) // 4))
		print('data size:', hex(len(data)))
		print('sram addr:', hex(sram_addr))
		print('end:', hex(sig_end), sig_end)

	if args.verbose > 1:
		print()
		print('=== CODE ===')
	if args.output:
		out = open(args.output, 'wb+')
	if version.startswith(b'CNN5x'):
		return
	segment_override = 0
	segment_override_credits = 0
	for address in range(len(code) // 4):
		x = read4(code[address*4:address*4+4])
		if x >> 17 != address:
			print('WARNING: code is not fully consecutive!')
		parity = (x >> 16) & 1
		inst = x & 0xFFFF
		if parity != compute_parity(inst):
			print(f'parity error at offset {address:04X}')

		if args.verbose:
			comment = ''
			newline = False
			#if inst & 0xFFF8 == 0x0020:
			#	# this is bullshit
			#	reg = inst & 7
			#	comment = f'mov dcr, r{reg}'
			#elif inst & 0xFFF8 == 0x0040:
			#	# this is bullshit
			#	reg = inst & 7
			#	comment = f'mov r{reg}, dcr'
			if inst == 0:
				comment = 'nop'
			elif inst & 0xFFF0 == 0x0000: # the mask is just a guess, depends on how much IRAM there is
				segment_override = ((inst & 0xF) - 1) << 12
				segment_override_credits = 2
				comment = f'seg 0x{segment_override:04X}'
			elif inst & 0xFF00 == 0x0400:
				# 0000 0010 xxxx xxxx - hardware macro?
				comment = f'{inst&0xff:3}'
			elif inst & 0x1000:
				# hhc1 clll llll llll - jump to 13-bit absolute address h:l
				# hh11 1lll llll llll - call to 13-bit absolute address h:l
				cc  = (inst & 0x0800) >> 11
				cc |= (inst & 0x2000) >> 12
				opname = ['jnz', 'jc', 'jz', 'call'][cc]
				# TODO: test how long it actually lasts
				if segment_override_credits > 0:
					segment = segment_override
					segment_override_credits -= 2 if cc == 3 else 1
				else:
					# by default addresses are implicitly within the current segment
					segment = address & ~0x1FFF
				high_bits = (inst & 0xC000) >> 3
				low_bits = inst & 0x07FF
				target = segment + (high_bits | low_bits)
				direction = '^' if target <= address else 'v'
				comment = f'{opname} --{direction}'
				if args.verbose > 1:
					comment += f' {target:04X}'
			elif inst & 0xF800 == 0x0800:
				# 0000 1rrr iiii iiii - load 8-bit immediate i to register r?
				register = (inst >> 8) & 7
				value = inst & 0xFF
				comment = f'mov r{register}, {value} (0x{value:02x})'
			elif inst & 0x7FFF == 0x0100:
				# ?000 0001 0000 0000 - return
				comment = 'return'
				if inst & 0x8000:
					comment += ' (somehow special)'
				newline = True
			elif inst & 0xFF7F == 0x0200:
				comment = 'return (px)'
				if inst & 0x0080:
					comment += ' (somehow special)'
				newline = True
			elif inst & 0xF8C0 == 0x60C0:
				rhs = inst & 0x0007
				lhs = (inst & 0x0038) >> 3
				dst = (inst & 0x0700) >> 8
				comment = f'sub r{dst}, r{lhs}, r{rhs}'
			elif inst & 0xF8C0 == 0xE0C0:
				src = inst & 0x0007
				imm = (inst & 0x0038) >> 3
				dst = (inst & 0x0700) >> 8
				comment = f'subi r{dst}, r{src}, {imm + 1}'
			else:
				regd    = (inst & 0b00000_111_00_000_000) >>  8
				reg2    = (inst & 0b00000_000_00_111_000) >>  3
				reg1    = (inst & 0b00000_000_00_000_111) >>  0
				opcode  = (inst & 0b00000_000_11_000_000) >>  6
				opcode |= (inst & 0b00001_000_00_000_000) >>  9
				opcode |= (inst & 0b00100_000_00_000_000) >> 10
				cond    = (inst & 0b11000_000_00_000_000) >> 14
				if opcode == 0x8:
					op = '&'
				elif opcode == 0x9:
					# also used for zero checks and for register->register moves
					op = '|'
				elif opcode == 0xB:
					op = '-'
				else:
					op = f'{opcode:X}'
				comment = f'r{regd} = r{reg1} {op} r{reg2}'
				comment += f' cond={cond:02b}'
				if cond == 0:
					pass
				elif cond == 1:
					comment += ' < 0?'
				elif cond == 2:
					comment += ' always'
				elif cond == 3:
					comment += ' == 0?'

			b = f'{inst:016b}'
			
			# avoid unnecessary diffs
			if args.verbose == 1 and inst & 0x1000:
				inst &= 0x3800
				ba = bytearray(b'a' * 16)
				for i in (2, 3, 4):
					ba[i] = ord(b[i])
				b = str(ba, 'ascii')

			bin_inst = f'{b[0:5]} {b[5:8]} {b[8:10]} {b[10:13]} {b[13:16]}'
			if args.verbose > 1:
				print(f'{address:04X}:  {inst:04X}  {bin_inst}  {comment}')
				if newline:
					print()
			else:
				print(f'{inst:04X}  {bin_inst}  {comment}')

		if args.output:
			b = struct.pack('>H', inst)
			out.write(b)

	if args.verbose > 1:
		print()
		print('=== DATA ===')
		hexdump(data)

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-v', '--verbose', action='count', default=0, help='0: header, 1: raw code, 2: header/code with annotations/data')
	parser.add_argument('files', nargs='+', help='input file(s)')
	parser.add_argument('-o', '--output', help='output file')
	parser.add_argument('--mystery', action='store_true')
	parser.add_argument('--raw', action='store_true')
	args = parser.parse_args()
	for path in args.files:
		handle_file(path, args)
