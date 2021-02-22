#!/usr/bin/env python3

import binascii
import re
import struct
import sys

instruction_list = []
instruction_dict = {}

class Operand:
	def __init__(self, desc, enc):
		matches = re.search(r'(?P<is_register>r?)\{(?P<name>[^:}]+)(:[^}]+)?\}', desc)
		self.name = matches.group('name')
		self.is_register = len(matches.group('is_register')) > 0
		self.mask = self.compute_mask(self.name[0], enc)

	def compute_mask(self, char, enc):
		return int(''.join(['1' if c == char else '0' for c in enc]), 2)

	def encode(self, string):
		if self.is_register:
			assert string.startswith('r')
			string = string.removeprefix('r')
		value = int(string, 16 if string.startswith('0x') else 10)
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

	def decode(self, inst):
		mask = self.mask
		size = 0
		value = 0
		while mask and inst:
			if mask & 1:
				value |= (inst & 1) << size
				size += 1
			inst >>= 1
			mask >>= 1
		return value

	def __repr__(self):
		return f'{self.name} ({self.mask:016b})'

def instruction(cls):
	enc = cls.encoding.replace(' ', '')
	mask = ''.join(['1' if c in '01' else '0' for c in enc])
	value = ''.join([c if c in '01' else '0' for c in enc])
	cls.encoding_mask = int(mask, 2)
	cls.encoding_value = int(value, 2)
	cls.name = cls.__name__
	cls.operand_list = [Operand(op, enc) for op in cls.operands.split(',') if op != '']
	instruction_list.append(cls)
	assert cls.name not in instruction_dict
	instruction_dict[cls.name] = cls
	return cls

@instruction
class nop:
	operands = ''
	encoding = '0000 0000 0000 0000'

@instruction
class seg:
	operands = '{seg}'
	encoding = '0000 0000 0000 00s1'

@instruction
class jz:
	operands = '0x{addr:04x}'
	encoding = 'aa11 0aaa aaaa aaaa'

@instruction
class jnz:
	operands = '0x{addr:04x}'
	encoding = 'aa01 0aaa aaaa aaaa'

@instruction
class jc:
	operands = '0x{addr:04x}'
	encoding = 'aa01 1aaa aaaa aaaa'

@instruction
class call:
	operands = '0x{addr:04x}'
	encoding = 'aa11 1aaa aaaa aaaa'

@instruction
class ret_1000:
	operands = '{imm1}'
	encoding = 'i000 0001 0000 0000'

@instruction
class ret_px:
	operands = '{imm1}'
	encoding = '0000 0010 i000 0000'

@instruction
class mov:
	operands = 'r{dst}, 0x{imm8:02x} # {imm8}'
	encoding = '0000 1ddd iiii iiii'

@instruction
class sub:
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0110 0ddd 11rr rlll'

@instruction
class subi:
	operands = 'r{dst}, r{src}, {imm3}'
	encoding = '1110 0ddd 11ii isss'

@instruction
class dw:
	operands = '0x{imm16:04x}'
	encoding = 'iiii iiii iiii iiii'

class Disassembler:
	def __init__(self, args):
		self.segment = 0
		self.mc = mc = Microcode(path=args.filename)
		if args.output:
			output = open(args.output, 'w+')
		else:
			output = sys.stdout
		print(f'.type {mc.mc_type}', file=output)
		print(f'.version {mc.version.decode("ascii")}', file=output)
		print(f'.sram_addr 0x{mc.sram_addr:04x}', file=output)
		for i in range(0, len(mc.code), 4):
			address = i // 4
			word = struct.unpack('>I', mc.code[i:i+4])[0] & 0xFFFF
			print('\t' + self.instruction(word).ljust(30) + f'# {address:04x}: {word:04x}', file=output)
		for i in range(0, len(mc.data), 8):
			word = mc.data[i:i+8]
			hex_word = ' '.join([f'{byte:02x}' for byte in word])
			readable = ''.join([chr(c) if c < 127 and c >= 32 else '.' for c in word])
			print(f'\t.data {hex_word} # {i:04x}: {readable}', file=output)
	
	def instruction(self, word):
		for inst in instruction_list:
			if word & inst.encoding_mask == inst.encoding_value:
				operands = {op.name: op.decode(word) for op in inst.operand_list}
				return f'{inst.name}'.ljust(10) + inst.operands.format(**operands)
		raise NotImplementedError('unknown instruction')

class Assembler:
	def __init__(self, args):
		self.address = 0
		self.label_to_addr = {}
		self.addr_to_label = {}
		self.mc = Microcode()
		with open(args.filename) as f:
			for line in f:
				word = self.handle_line(line)
				if word is not None:
					self.mc.code.append(word)
		self.mc.save(args.output)

	def handle_line(self, line):
		line = line.split('#')[0].strip()
		if not line:
			return None
		if line.endswith(':'):
			label = line[:-1]
			self.label_to_addr[label] = self.address
			self.addr_to_label[self.address] = label
			return None
		components = line.split(None, 1)
		opcode = components[0]
		arguments = []
		if len(components) == 2:
			arguments = [arg.strip() for arg in components[1].split(',')]
		if opcode.startswith('.'):
			return getattr(self, 'handle_' + opcode[1:])(*arguments)
		inst = instruction_dict[opcode]
		word = inst.encoding_value
		for i, param in enumerate(inst.operand_list):
			arg = arguments[i]
			if param.name == 'addr' and arg in self.label_to_addr:
				arg = str(self.label_to_addr[arg] & 0x1FFF)
			word |= param.encode(arg)
		self.address += 1
		return word

	def handle_type(self, mc_type):
		self.mc.mc_type = int(mc_type)

	def handle_version(self, version):
		self.mc.version = version.encode('ascii')

	def handle_sram_addr(self, addr):
		self.mc.sram_addr = int(addr, 16)

	def handle_data(self, hex_bytes):
		self.mc.data += binascii.unhexlify(hex_bytes.replace(' ', ''))

class Microcode:
	def __init__(self, path=None):
		if path is not None:
			self.load(path)
		else:
			self.mc_type = 1
			self.version = b'undefined'
			self.sram_addr = 0
			self.code = []
			self.data = b''
			self.signature = b''

	def load(self, path):
		with open(args.filename, 'rb') as f:
			d = f.read()
		self.mc_type, self.version, code_len, data_len, self.sram_addr = struct.unpack_from('>B31sIIQ', d)
		self.version = self.version.rstrip(b'\x00')
		if self.version.startswith(b'CNN5x'):
			code_len *= 2
		else:
			code_len *= 4

		def alignup16(x):
			return (x + 15) & ~15

		code_start = 0x30
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

	def save(self, path):
		with open(path, 'wb+') as f:
			f.write(struct.pack('>B31sIIQ', self.mc_type, self.version, len(self.code), len(self.data), self.sram_addr))
			code_section = b''.join([struct.pack('>I', i << 17 | self.compute_parity(word) << 16 | word) for i, word in enumerate(self.code)])
			code_section += b'\x00' * (16 - len(code_section) % 16)
			f.write(code_section)
			f.write(self.data)
			f.write(self.signature)

if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('filename')
	parser.add_argument('-o', '--output')
	parser.add_argument('-d', '--disassemble', action='store_true')
	args = parser.parse_args()
	if args.disassemble:
		Disassembler(args)
	else:
		Assembler(args)
