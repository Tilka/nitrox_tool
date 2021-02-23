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

	def encode_string(self, string):
		if self.is_register:
			assert string.startswith('r')
			string = string.removeprefix('r')
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
		if self.name == 'addr':
			value |= assembler.segment << 13
			assembler.xrefs.add(value)
			value = assembler.label(value)
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
	operands = '{addr}'
	encoding = 'aa11 0aaa aaaa aaaa'

@instruction
class jnz:
	operands = '{addr}'
	encoding = 'aa01 0aaa aaaa aaaa'

@instruction
class jc:
	operands = '{addr}'
	encoding = 'aa01 1aaa aaaa aaaa'

@instruction
class call:
	operands = '{addr}'
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
	operands = 'r{dst}, r{src}, {imm3_minus_one}'
	encoding = '1110 0ddd 11ii isss'

@instruction
class dw:
	operands = '0x{imm16:04x}'
	encoding = 'iiii iiii iiii iiii'

class Disassembler:
	def __init__(self, args):
		self.seg_duration = 0
		self.mc = mc = Microcode(path=args.filename)
		self.address_to_label = {}
		if args.labels:
			for line in open(args.labels, 'r'):
				address, label = line.rstrip('\n').split(' ')
				self.address_to_label[int(address, 16)] = label
		if args.output:
			output = open(args.output, 'w+')
		else:
			output = sys.stdout
		print(f'.type {mc.mc_type}', file=output)
		print(f'.version {mc.version}', file=output)
		print(f'.sram_addr 0x{mc.sram_addr:04x}', file=output)
		lines = []
		self.xrefs = set()
		for i in range(0, len(mc.code), 4):
			address = i // 4
			if self.seg_duration == 0:
				self.segment = address >> 13
			else:
				self.seg_duration -= 1
			word = struct.unpack('>I', mc.code[i:i+4])[0] & 0xFFFF
			opcode, operands = self.instruction(word)
			asm = (opcode.ljust(10) + operands).ljust(29)
			lines.append(f'\t{asm} # {address:04x}: {word:04x}')
			# hack to make segmented addressing work,
			# in reality the segment is probably just state that gets pushed onto the call stack
			if opcode == 'seg':
				self.segment = (word >> 1) & 1
				self.seg_duration = 2
			elif opcode == 'call':
				self.seg_duration = 0
		for i, line in enumerate(lines):
			if i in self.xrefs:
				print(self.label(i) + ':', file=output)
			print(line, file=output)
		for i in range(0, len(mc.data), 8):
			word = mc.data[i:i+8]
			hex_word = ' '.join([f'{byte:02x}' for byte in word])
			readable = ''.join([chr(c) if c < 127 and c >= 32 else '.' for c in word])
			print(f'\t.data {hex_word} # {i:04x}: {readable}', file=output)
		for i in range(0, len(mc.signature), 8):
			word = mc.signature[i:i+8]
			hex_word = ' '.join([f'{byte:02x}' for byte in word])
			print(f'\t.sig  {hex_word} # {i:04x}', file=output)
	
	def instruction(self, word):
		for inst in instruction_list:
			if word & inst.encoding_mask == inst.encoding_value:
				operands = {op.name: op.decode(word, self) for op in inst.operand_list}
				return inst.name, inst.operands.format(**operands)
		raise NotImplementedError('unknown instruction')

	def label(self, address):
		if address in self.address_to_label:
			return self.address_to_label[address]
		else:
			return f'label_{address:04x}'

class Assembler:
	def __init__(self, args):
		self.current_address = 0
		self.label_to_addr = {}
		self.mc = Microcode()
		self.fixups = []
		with open(args.filename) as f:
			for line in f:
				self.handle_line(line)
		for pos, label, operand in self.fixups:
			self.mc.code[pos] |= operand.encode_value(self.label_to_addr[label] & 0x1FFF)
		self.mc.save(args.output)

	def handle_line(self, line):
		line = line.split('#')[0].strip()
		if not line:
			return
		if line.endswith(':'):
			label = line[:-1]
			assert label not in self.label_to_addr
			self.label_to_addr[label] = self.current_address
			return
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
			if param.name == 'addr' and not arg.startswith('0x'):
				self.fixups.append((self.current_address, arg, param))
			else:
				word |= param.encode_string(arg)
		self.mc.code.append(word)
		self.current_address += 1

	def handle_type(self, mc_type):
		self.mc.mc_type = int(mc_type)

	def handle_version(self, version):
		self.mc.version = version

	def handle_sram_addr(self, addr):
		self.mc.sram_addr = int(addr, 16)

	def handle_data(self, hex_bytes):
		self.mc.data += binascii.unhexlify(hex_bytes.replace(' ', ''))

	def handle_sig(self, hex_bytes):
		self.mc.signature += binascii.unhexlify(hex_bytes.replace(' ', ''))

class Microcode:
	def __init__(self, path=None):
		if path is not None:
			self.load(path)
		else:
			self.mc_type = 1
			self.version = 'undefined'
			self.sram_addr = 0
			self.code = []
			self.data = b''
			self.signature = b''

	def load(self, path):
		with open(args.filename, 'rb') as f:
			d = f.read()
		self.mc_type, self.version, code_len, data_len, self.sram_addr = struct.unpack_from('>B31sIIQ', d)
		self.version = self.version.rstrip(b'\x00').decode('ascii')
		if self.version.startswith('CNN5x'):
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

	def pad16(self, blob):
		len_mod_16 = len(blob) % 16
		return blob + (b'' if len_mod_16 == 0 else b'\x00' * (16 - len_mod_16))

	def save(self, path):
		with open(path, 'wb+') as f:
			f.write(struct.pack('>B31sIIQ', self.mc_type, self.version.encode('ascii'), len(self.code), len(self.data), self.sram_addr))
			code = b''.join([struct.pack('>I', i << 17 | self.compute_parity(word) << 16 | word) for i, word in enumerate(self.code)])
			f.write(self.pad16(code))
			f.write(self.pad16(self.data))
			f.write(self.signature)

if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('filename')
	parser.add_argument('-o', '--output')
	parser.add_argument('-d', '--disassemble', action='store_true')
	parser.add_argument('-l', '--labels')
	args = parser.parse_args()
	if args.disassemble:
		Disassembler(args)
	else:
		Assembler(args)
