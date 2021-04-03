#!/usr/bin/env python3

import binascii
import re
import struct
import sys

from inst import *

class Operand:
	def __init__(self, desc, enc):
		matches = re.search(r'((?P<is_main_reg>r)|(?P<is_temp_reg>a|b|c|d))?\{(?P<name>[^:}]+)(:[^}]+)?\}', desc)
		self.name = matches.group('name')
		self.is_main_reg = matches.group('is_main_reg') is not None
		self.is_temp_reg = matches.group('is_temp_reg') is not None
		self.mask = self.compute_mask(self.name[0], enc)

	def compute_mask(self, char, enc):
		return int(''.join(['1' if c == char else '0' for c in enc]), 2)

	def encode_string(self, string):
		if self.is_main_reg:
			assert string.startswith('r')
			string = string.removeprefix('r')
		if self.is_temp_reg:
			string = string[1:]
		value = int(string, 16 if string.startswith('0x') else 10)
		return self.encode_value(value)

	def encode_value(self, value):
		if self.name == 'imm3_minus_one':
			value -= 1
		mask = self.mask
		enc = 0
		pos = 0
		while mask:
			if mask & 1:
				enc |= (value & 1) << pos
				value >>= 1
			mask >>= 1
			pos += 1
		assert value == 0
		return enc

	def decode(self, inst, assembler):
		mask = self.mask
		size = 0
		value = 0
		while mask and inst:
			if mask & 1:
				value |= (inst & 1) << size
				size += 1
			inst >>= 1
			mask >>= 1
		if self.name.startswith('addr'):
			value |= assembler.segment << 13
			# HACK
			if self.name == 'addr_':
				assembler.call_xrefs.add(value)
				value = assembler.label('fun', value)
			else:
				assembler.jump_xrefs.add(value)
				value = assembler.label('loc', value)
		elif self.name == 'imm3_minus_one':
			value += 1
		return value

	def __repr__(self):
		return f'{self.name} ({self.mask:016b})'

def instruction(cls):
	enc = cls.encoding.replace(' ', '')
	mask = ''.join(['1' if c in '01' else '0' for c in enc])
	value = ''.join([c if c in '01' else '0' for c in enc])
	cls.encoding_mask = int(mask, 2)
	cls.encoding_value = int(value, 2)
	cls.name = cls.__name__.removesuffix('_')
	cls.operand_list = [Operand(op, enc) for op in cls.operands.split(',') if op != '']
	instruction_list.append(cls)
	assert cls.name not in instruction_dict
	instruction_dict[cls.name] = cls
	return cls

def do_import(gen):
	if gen == 1:
		import lite
	elif gen == 2 or gen == 3 or gen == 5 or gen == 8:
		import px
	else:
		raise NotImplementedError(gen)

class Disassembler:
	def __init__(self, filename, args):
		self.mc = mc = Microcode(filename, args)
		if args.output:
			output = open(args.output, 'w+')
		else:
			output = sys.stdout
		if not args.stat:
			if args.disassemble:
				print(f'.type {mc.mc_type}', file=output)
			if True:
				print(f'.version {mc.version} ; {filename}', file=output)
			if args.disassemble:
				print(f'.sram_addr 0x{mc.sram_addr:04x}', file=output)
			if not args.disassemble:
				return
		self.segment = 0
		self.seg_duration = 0
		self.address_to_label = {}
		if args.labels:
			for line in open(args.labels, 'r'):
				address, label = line.rstrip('\n').split(' ')
				self.address_to_label[int(address, 16)] = label
		lines = []
		self.call_xrefs = set()
		self.jump_xrefs = set()
		do_import(self.mc.gen)
		for i in range(0, len(mc.code), self.mc.inst_size):
			address = i // self.mc.inst_size
			if self.seg_duration > 0:
				self.seg_duration -= 1
			elif not args.diff:
				self.segment = address >> 13
			if self.mc.inst_size == 2:
				if self.mc.gen == 5:
					word = struct.unpack('<H', mc.code[i:i+2])[0]
				else:
					word = struct.unpack('>H', mc.code[i:i+2])[0]
			else:
				word = struct.unpack('>I', mc.code[i:i+4])[0] & 0xFFFF
			if args.diff and word & 0x1000:
				word &= 0x3800
			opcode, operands = self.instruction(word)
			asm = (opcode.ljust(10) + operands).ljust(29)
			if args.stat:
				line = f'{word:04x} ({word>>12&15:04b} {word>>8&15:04b} {word>>4&15:04b} {word&15:04b}) {asm}'
			elif args.diff:
				line = f'\t{asm} ; 0x{word:04x} ({word>>12&15:04b} {word>>8&15:04b} {word>>4&15:04b} {word&15:04b})'
			else:
				line = f'\t{asm} ; {address:04x}: 0x{word:04x} ({word>>12&15:04b} {word>>8&15:04b} {word>>4&15:04b} {word&15:04b})'
			# hack to make segmented addressing work,
			# in reality the segment is probably just state that gets pushed onto the call stack
			if opcode == 'seg':
				# completely ignore seg when diffing
				if args.diff:
					continue
				self.segment = (word >> 1) & 1
				self.seg_duration = 2
			elif opcode == 'call':
				self.seg_duration = 0
			lines.append(line)
			is_control_flow = opcode.startswith('j')
			if is_control_flow and not args.stat and not args.diff:
				lines[-1] += '\n'
		for i, line in enumerate(lines):
			if not args.stat:
				if i and not lines[i - 1].endswith('\n') and (i in self.call_xrefs or i in self.jump_xrefs):
					print(file=output)
				if i in self.call_xrefs:
					print(self.label('fun', i) + ':', file=output)
				if i in self.jump_xrefs:
					print(self.label('loc', i) + ':', file=output)
			print(line, file=output)
		if args.stat:
			return
		for i in range(0, len(mc.data), 8):
			word = mc.data[i:i+8]
			hex_word = ' '.join([f'{byte:02x}' for byte in word])
			readable = ''.join([chr(c) if c < 127 and c >= 32 else '.' for c in word])
			print(f'\t.data {hex_word} ; {i:04x}: {readable}', file=output)
		for i in range(0, len(mc.signature), 8):
			word = mc.signature[i:i+8]
			hex_word = ' '.join([f'{byte:02x}' for byte in word])
			print(f'\t.sig  {hex_word} ; {i:04x}', file=output)
	
	def instruction(self, word):
		for inst in instruction_list:
			if word & inst.encoding_mask == inst.encoding_value:
				opcode = inst.name
				if inst.encoding[0] == '^' and word & 0x8000:
					opcode += '^'
				if inst.encoding[1] == '.' and word & 0x4000:
					opcode += '.'
				operands = {op.name: op.decode(word, self) for op in inst.operand_list}
				return opcode, inst.operands.format(**operands)
		raise NotImplementedError(f'unknown instruction 0x{word:04x}')

	def label(self, prefix, address):
		if address in self.address_to_label:
			return self.address_to_label[address]
		else:
			return f'{prefix}_{address:04x}'

class Assembler:
	def __init__(self, filename, args):
		self.current_address = 0
		self.label_to_addr = {}
		self.mc = Microcode()
		self.fixups = []
		with open(filename) as f:
			for line in f:
				self.handle_line(line)
		for pos, label, operand in self.fixups:
			self.mc.code[pos] |= operand.encode_value(self.label_to_addr[label] & 0x1FFF)
		self.mc.save(args.output)

	def handle_line(self, line):
		line = line.split(';')[0].strip()
		if not line:
			return
		if line.endswith(':'):
			label = line[:-1]
			#assert label not in self.label_to_addr
			self.label_to_addr[label] = self.current_address
			return
		components = line.split(None, 1)
		opcode = components[0]
		arguments = []
		if len(components) == 2:
			arguments = [arg.strip() for arg in components[1].split(',')]
		if opcode.startswith('.'):
			return getattr(self, 'handle_' + opcode[1:])(*arguments)
		if len(instruction_list) == 0:
			do_import(self.mc.gen)
		word = 0
		if opcode.endswith('.'):
			opcode = opcode.removesuffix('.')
			word |= 0x4000
		if opcode.endswith('^'):
			opcode = opcode.removesuffix('^')
			word |= 0x8000
		inst = instruction_dict[opcode]
		assert word & 0x4000 == 0 or inst.encoding[1] == '.'
		assert word & 0x8000 == 0 or inst.encoding[0] == '^'
		word |= inst.encoding_value
		for i, param in enumerate(inst.operand_list):
			arg = arguments[i]
			if param.name.startswith('addr') and not arg.startswith('0x'):
				self.fixups.append((self.current_address, arg, param))
			else:
				word |= param.encode_string(arg)
		self.mc.code.append(word)
		self.current_address += 1

	def handle_type(self, mc_type):
		self.mc.mc_type = int(mc_type)

	def handle_version(self, version):
		self.mc.set_version(version)

	def handle_sram_addr(self, addr):
		self.mc.sram_addr = int(addr, 16)

	def handle_data(self, hex_bytes):
		self.mc.data += binascii.unhexlify(hex_bytes.replace(' ', ''))

	def handle_sig(self, hex_bytes):
		self.mc.signature += binascii.unhexlify(hex_bytes.replace(' ', ''))

class Microcode:
	def __init__(self, path=None, args=None):
		if path is not None:
			self.load(path, args)
		else:
			self.init_empty()

	def init_empty(self):
		self.mc_type = 1
		self.version = 'undefined'
		self.sram_addr = 0
		self.code = []
		self.data = b''
		self.signature = b''

	def set_version(self, version):
		self.version = version
		prefix = self.version.split('-')[0]
		generations = [
			(1, ['CN1000', 'CNLite', 'CNlite']),
			(2, ['CNPx']),
			(3, ['CN35x', 'CNN35x']),
			(5, ['CNN5x']),
			(8, ['CNT8x', 'O8x'])]
		for gen, prefixes in generations:
			if prefix in prefixes:
				self.gen = gen
				break
		else:
			raise NotImplementedError(repr(prefix))

	def load(self, path, args):
		with open(path, 'rb') as f:
			d = f.read()
		if args.raw:
			self.init_empty()
			self.code = d
			self.gen = args.arch
			return
		if d[4:7] == b'O8x':
			self.mc_type, version, code_len, data_len, self.sram_addr = struct.unpack_from('>I44sIIQ', d)
			code_start = 0x40
		else:
			self.mc_type, version, code_len, data_len, self.sram_addr = struct.unpack_from('>B31sIIQ', d)
			code_start = 0x30
		self.set_version(version.rstrip(b'\x00').decode('ascii'))

		def alignup16(x):
			return (x + 15) & ~15

		if self.gen >= 5:
			self.inst_size = 2
		else:
			self.inst_size = 4

		code_len *= self.inst_size
		code_end = code_start + code_len
		data_start = alignup16(code_end)
		data_end = data_start + data_len
		sig_start = alignup16(data_end)
		sig_end = sig_start + 256

		self.code = d[code_start:code_end]
		self.data = d[data_start:data_end]
		self.signature = d[sig_start:sig_end]
		
	def compute_parity(self, x):
		parity = 0
		while x:
			parity ^= x & 1
			x >>= 1
		return parity

	def pad16(self, blob):
		len_mod_16 = len(blob) % 16
		return blob + (b'' if len_mod_16 == 0 else b'\x00' * (16 - len_mod_16))

	def save(self, path):
		assert len(self.code) < 13354
		with open(path, 'wb+') as f:
			f.write(struct.pack('>B31sIIQ', self.mc_type, self.version.encode('ascii'), len(self.code), len(self.data), self.sram_addr))
			code = b''.join([struct.pack('>I', i << 17 | self.compute_parity(word) << 16 | word) for i, word in enumerate(self.code)])
			f.write(self.pad16(code))
			f.write(self.pad16(self.data))
			f.write(self.signature)

if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('filename', nargs='+', help='input file(s)')
	parser.add_argument('-o', '--output', help='output file')
	parser.add_argument('-l', '--labels', help='file with "offset, label" pairs')
	parser.add_argument('-a', '--assemble', action='store_true', help='assemble source code to binary')
	parser.add_argument('-d', '--disassemble', action='store_true', help='print full disassembly')
	parser.add_argument('--stat', action='store_true', help='optimize output for computing instruction stats')
	parser.add_argument('--diff', action='store_true', help='optimize output for diffing (lossy)')
	parser.add_argument('--raw', action='store_true', help='load raw code blob')
	parser.add_argument('--arch', type=int, help='force architecture (1, 2, 3, 5, 8), necessary when using --raw')
	args = parser.parse_args()
	for filename in args.filename:
		if args.assemble:
			Assembler(filename, args)
		else:
			Disassembler(filename, args)
