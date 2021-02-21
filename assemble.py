#!/usr/bin/env python3

import struct

instruction_list = []
instruction_dict = {}

class Operand:
	def __init__(self, name, enc):
		self.is_register = name.startswith('reg_')
		self.name = name.removeprefix('reg_')
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
		if self.is_register:
			return f'r{value}'
		else:
			return f'0x{value:x}'

	def __repr__(self):
		return f'{self.name} ({self.mask:016b})'

def instruction(cls):
	enc = cls.encoding.replace(' ', '')
	mask = ''.join(['1' if c in '01' else '0' for c in enc])
	value = ''.join([c if c in '01' else '0' for c in enc])
	cls.encoding_mask = int(mask, 2)
	cls.encoding_value = int(value, 2)
	cls.name = cls.__name__
	cls.operand_list = [Operand(op, enc) for op in cls.operands.split(', ') if op != '']
	#print(cls.name, cls.operands, cls.operand_list)
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
	operands = 'seg'
	encoding = '0000 0000 0000 00ss'

@instruction
class jz:
	operands = 'addr'
	encoding = 'aa11 0aaa aaaa aaaa'

@instruction
class jnz:
	operands = 'addr'
	encoding = 'aa01 0aaa aaaa aaaa'

@instruction
class jc:
	operands = 'addr'
	encoding = 'aa01 1aaa aaaa aaaa'

@instruction
class call:
	operands = 'addr'
	encoding = 'aa11 1aaa aaaa aaaa'

@instruction
class ret_1000:
	operands = 'imm1'
	encoding = 'i000 0001 0000 0000'

@instruction
class ret_px:
	operands = 'imm1'
	encoding = '0000 0010 i000 0000'

@instruction
class mov:
	operands = 'reg_dst, imm8'
	encoding = '0000 1ddd iiii iiii'

@instruction
class sub:
	operands = 'reg_dst, reg_lhs, reg_rhs'
	encoding = '0110 0ddd 11rr rlll'

@instruction
class subi:
	operands = 'reg_dst, reg_src, imm3'
	encoding = '1110 0ddd 11ii isss'

@instruction
class dw:
	operands = 'imm16'
	encoding = 'iiii iiii iiii iiii'

class Disassembler:
	def __init__(self):
		self.segment = 0
	
	def disassemble(self, word):
		for inst in instruction_list:
			if word & inst.encoding_mask == inst.encoding_value:
				operands = ', '.join([op.decode(word) for op in inst.operand_list])
				return f'{inst.name}\t{operands}'
		raise NotImplementedError('unknown instruction')

class Assembler:
	def __init__(self):
		self.address = 0
		self.label_to_addr = {}
		self.addr_to_label = {}

	def assemble(self, line):
		line = line.split('#')[0].strip()
		if not line:
			return b''
		if line.endswith(':'):
			label = line[:-1]
			self.label_to_addr[label] = self.address
			self.addr_to_label[self.address] = label
			return b''
		components = line.split(None, 1)
		opcode = components[0]
		arguments = []
		if len(components) == 2:
			arguments = [arg.strip() for arg in components[1].split(',')]
		if opcode == '.org':
			self.address = int(arguments[0], 16)
			return b''
		
		inst = instruction_dict[opcode]
		word = inst.encoding_value
		for i, param in enumerate(inst.operand_list):
			arg = arguments[i]
			if param.name == 'addr' and arg in self.label_to_addr:
				arg = str(self.label_to_addr[arg] & 0x1FFF)
			word |= param.encode(arg)
		self.address += 1
		return word

def read4(d):
	return struct.unpack('>I', d[0:4])[0]

def round16(x):
	return (x + 15) & ~15

class Microcode:
	def __init__(self, mc_type=1, version=b'CNPx-MC-SSL-MAIN-0018', sram_addr=0x1fb8, code=None, data=b'', signature=b'', path=None):
		if path is not None:
			self.load(path)
		else:
			self.mc_type = mc_type
			self.version = version
			self.sram_addr = sram_addr
			self.code = [] if code is None else code
			self.data = b''
			self.signature = signature

	def load(self, path):
		with open(args.filename, 'rb') as f:
			d = f.read()
		self.mc_type, self.version, code_len, data_len, self.sram_addr = struct.unpack_from('>B31sIIQ', d)
		if self.version.startswith(b'CNN5x'):
			code_len *= 2
		else:
			code_len *= 4

		code_start = 0x30
		code_end = code_start + code_len
		data_start = round16(code_end)
		data_end = data_start + data_len
		sig_start = round16(data_end)
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
			f.write(b''.join([struct.pack('>I', i << 17 | self.compute_parity(word) << 16 | word) for i, word in enumerate(self.code)]))
			f.write(self.data)
			f.write(self.signature)

def disassemble(args):
	mc = Microcode(path=args.filename)
	disasm = Disassembler()
	for address in range(len(mc.code) // 4):
		word = read4(mc.code[address*4:address*4+4]) & 0xFFFF
		#print(f'{address:04x}: {word:04x}', disasm.disassemble(word))
		print(disasm.disassemble(word))

def assemble(args):
	asm = Assembler()
	mc = Microcode()
	with open(args.filename) as f:
		for line in f:
			mc.code.append(asm.assemble(line))
	mc.save(args.output)

if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('filename')
	parser.add_argument('-o', '--output')
	parser.add_argument('-d', '--disassemble', action='store_true')
	args = parser.parse_args()
	if args.disassemble:
		disassemble(args)
	else:
		assemble(args)
