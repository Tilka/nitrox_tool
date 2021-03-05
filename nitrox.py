#!/usr/bin/env python3

# TODO: why does the 'and' in CNPx-MC-SSL-MAIN-0018 at 0x00a4 have a '.'?
# TODO; why does the 'or' at 0x00f6 have a '.'?

import binascii
import re
import struct
import sys

instruction_list = []
instruction_dict = {}

class Operand:
	def __init__(self, desc, enc):
		matches = re.search(r'((?P<is_main_reg>r)|(?P<is_addr_reg>a))?\{(?P<name>[^:}]+)(:[^}]+)?\}', desc)
		self.name = matches.group('name')
		self.is_main_reg = matches.group('is_main_reg') is not None
		self.is_addr_reg = matches.group('is_addr_reg') is not None
		self.mask = self.compute_mask(self.name[0], enc)

	def compute_mask(self, char, enc):
		return int(''.join(['1' if c == char else '0' for c in enc]), 2)

	def encode_string(self, string):
		if self.is_main_reg:
			assert string.startswith('r')
			string = string.removeprefix('r')
		if self.is_addr_reg:
			assert string.startswith('a')
			string = string.removeprefix('a')
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

@instruction
class nop:
	operands = ''
	encoding = '0000 0000 0000 0000'
	def emulate():
		pass

@instruction
class seg:
	operands = '{seg}'
	encoding = '0000 0000 0000 00s1'
	def emulate(state, segment):
		state.segment = segment

@instruction
class op0020: # TODO (lite)
	operands = 'r{reg}'
	encoding = '0000 0000 0010 0rrr'

@instruction
class op0040: # TODO (lite)
	operands = 'r{reg}'
	encoding = '0000 0000 0100 0rrr'

@instruction
class wait_input:
	operands = ''
	encoding = '0000 0000 1000 0000'

@instruction
class wait_other:
	operands = ''
	encoding = '0000 0001 1000 0000'

@instruction
class jz:
	operands = '{addr}'
	encoding = 'aa11 0aaa aaaa aaaa'
	def emulate(state, addr):
		if state.result == 0:
			state.pc = (state.segment << 13) | addr

@instruction
class jnz:
	operands = '{addr}'
	encoding = 'aa01 0aaa aaaa aaaa'
	def emulate(state, addr):
		if state.result != 0:
			state.pc = (state.segment << 13) | addr

@instruction
class js:
	operands = '{addr}'
	encoding = 'aa01 1aaa aaaa aaaa'
	def emulate(state, addr):
		if state.result & 0x8000:
			state.pc = (state.segment << 13) | addr

@instruction
class call:
	operands = '{addr_}'
	encoding = 'aa11 1aaa aaaa aaaa'
	def emulate(state, addr):
		assert len(state.call_stack) < 32
		state.call_stack.append(state.pc)
		state.pc = (state.segment << 13) | addr

@instruction
class ret_1000:
	operands = '{imm1}'
	encoding = 'i000 0001 0000 0000'

@instruction
class ret_px:
	operands = '{imm1}'
	encoding = '0000 0010 i000 0000'
	def emulate(state, imm1): # TODO: what does imm1 do?
		state.pc = state.call_stack.pop()
		state.segment = state.pc >> 13

@instruction
class op0300: # TODO
	operands = '0x{imm8:02x}'
	encoding = '^000 0011 iiii iiii'

@instruction
class op0400: # TODO (lite)
	operands = '0x{imm8:02x}'
	encoding = '0000 0100 iiii iiii'

@instruction
class op0500: # TODO
	operands = 'r{reg}'
	encoding = '0000 0101 0000 0rrr'

@instruction
class op0600: # TODO
	operands = 'r{reg}'
	encoding = '0000 0110 0000 0rrr'

@instruction
class op0700: # TODO
	operands = '0x{imm8:02x}'
	encoding = '^000 0111 iiii iiii'

@instruction
class li: # load immediate
	operands = 'r{dst}, 0x{imm8:02x} ; {imm8}'
	encoding = '0.00 1ddd iiii iiii'
	def emulate(state, dst, imm8):
		state.main_reg[dst] = imm8

@instruction
class and_: # TODO: why does the 'and' in CNPx-MC-SSL-MAIN-0018 at 0x00a4 have a '.'?
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0.10 0ddd 00rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] & state.main_regs[rhs]

@instruction
class or_:
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0.10 0ddd 01rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] | state.main_regs[rhs]

@instruction
class add:
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0.10 0ddd 10rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] + state.main_regs[rhs]

@instruction
class sub:
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0.10 0ddd 11rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] - state.main_regs[rhs]

@instruction
class shli:
	operands = 'r{dst}, r{lhs}, {imm4}'
	encoding = 'i.10 1ddd 00ii illl'
	def emulate(state, dst, lhs, imm4):
		state.main_reg[dst] = (state.main_reg[lhs] << imm4) & 0xFFFF

@instruction
class shri:
	operands = 'r{dst}, r{lhs}, {imm4}'
	encoding = 'i.10 1ddd 01ii illl'
	def emulate(state, dst, lhs, imm4):
		state.main_reg[dst] = state.main_reg[lhs] >> imm4

@instruction
class la: # load address register (16 bits)
	operands = 'a{dst}, r{src}'
	encoding = '^010 1ddd 1000 0sss'
	def emulate(state, dst, src):
		state.addr_reg[dst] = state.main_reg[src]

@instruction
class la1: # TODO: different register or upper 32 bits?
	operands = 'a{dst}, r{src}'
	encoding = '^010 1ddd 1000 1sss'

@instruction
class la_hi: # load address register (high 8 bits)
	operands = 'a{dst}, r{src}'
	encoding = '^010 1ddd 1001 0sss'
	def emulate(state, dst, src):
		state.addr_reg[dst] &= 0xFF
		state.addr_reg[dst] |= (state.main_reg[src] & 0xFF) << 8

@instruction
class la_hi1: # TODO
	operands = 'a{dst}, r{src}'
	encoding = '^010 1ddd 1001 1sss'

@instruction
class la_lo: # load address register (low 8 bits)
	operands = 'a{dst}, r{src}'
	encoding = '^010 1ddd 1010 0sss'
	def emulate(state, dst, src):
		state.addr_reg[dst] &= 0xFF00
		state.addr_reg[dst] |= state.main_reg[src] & 0xFF

@instruction
class la_lo1: # TODO
	operands = 'a{dst}, r{src}'
	encoding = '^010 1ddd 1010 1sss'

@instruction
class input: # read high-level operation, TODO: what does it do for offsets higher than 32?
	operands = 'r{dst}, r{src}'
	encoding = '^010 1ddd 1011 0sss'
	def emulate(state, dst, src):
		# main_reg[src] is an offset
		raise NotImplementedError

@instruction
class align8:
	operands = 'r{dst}, r{src}'
	encoding = '0.10 1ddd 1011 1sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = (state.main_reg[src] + 7) & -7

@instruction
class align16:
	operands = 'r{dst}, r{src}'
	encoding = '1.10 1ddd 1011 1sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = (state.main_reg[src] + 15) & -15

@instruction
class sa: # store address register to GPR (16 bits)
	operands = 'r{dst}, a{src}'
	encoding = '^.10 1ddd 1100 0sss'

@instruction
class sa1: # TODO
	operands = 'r{dst}, a{src}'
	encoding = '^.10 1ddd 1100 1sss'

@instruction
class sa_hi:
	operands = 'r{dst}, a{src}'
	encoding = '^.10 1ddd 1101 0sss'

@instruction
class sa_hi1: # TODO
	operands = 'r{dst}, a{src}'
	encoding = '^.10 1ddd 1101 1sss'

@instruction
class sa_lo:
	operands = 'r{dst}, a{src}'
	encoding = '^.10 1ddd 1110 0sss'

@instruction
class sa_lo1: # TODO
	operands = 'r{dst}, a{src}'
	encoding = '^.10 1ddd 1110 1sss'

@instruction
class not_:
	operands = 'r{dst}, r{src}'
	encoding = '^.10 1ddd 1111 0sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = ~state.main_reg[src] & 0xFFFF

@instruction
class op28f8: # TODO (seems to always write 0x0006)
	operands = 'r{dst}, a{src}'
	encoding = '^.10 1ddd 1111 1sss'

@instruction
class op4000: # TODO
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0100 0ddd 00rr rlll'

@instruction
class op4040: # TODO
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0100 0ddd 01rr rlll'

@instruction
class op4840: # TODO
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0100 1ddd 01rr rlll'

@instruction
class op8000: # TODO
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '1000 0ddd 00rr rlll'

@instruction
class op8040: # TODO
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '1000 0ddd 01rr rlll'

@instruction
class op8080: # TODO
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '1000 0ddd 10rr rlll'

@instruction
class op80c0: # TODO
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '1000 0ddd 11rr rlll'

@instruction
class lis: # load immediate shifted (flags are set according to the whole 16-bit register)
	operands = 'r{dst}, 0x{imm8:02x} ; {imm8}'
	encoding = '1.00 1iii iiii iddd'
	def emulate(state, dst, imm8):
		state.main_reg[dst] = (imm8 << 8) | (state.main_regs[dst] & 0xFF)

@instruction
class andi:
	operands = 'r{dst}, r{lhs}, {imm3_minus_one}'
	encoding = '1.10 0ddd 00ii illl'
	def emulate(state, dst, lhs, imm3_minus_one):
		state.main_reg[dst] = state.main_reg[lhs] & imm3_minus_one

@instruction
class opa040: # TODO (it's not ori, changes hash output)
	operands = 'r{dst}, r{lhs}, {imm3}'
	encoding = '1010 0ddd 01ii illl'

@instruction
class addi:
	operands = 'r{dst}, r{lhs}, {imm3_minus_one}'
	encoding = '1.10 0ddd 10ii illl'
	def emulate(state, dst, lhs, imm3_minus_one):
		state.main_regs[dst] = state.main_regs[lhs] + imm3_minus_one

@instruction
class subi:
	operands = 'r{dst}, r{lhs}, {imm3_minus_one}'
	encoding = '1.10 0ddd 11ii illl'
	def emulate(state, dst, lhs, imm3_minus_one):
		state.main_regs[dst] = state.main_regs[lhs] - imm3_minus_one

#@instruction
#class opa880: # TODO
#	# imm3=7: align lhs to 16, i.e. (lhs + 15) & -15
#	operands = 'r{dst}, r{lhs}, r{rhs}'
#	encoding = '1010 1ddd 10rr rlll'

#@instruction
#class opa8c0: # TODO (the '.' is probably correct)
#	operands = 'r{dst}, r{lhs}, r{rhs}'
#	encoding = '1.10 1ddd 11rr rlll'

@instruction
class dw:
	operands = '0x{imm16:04x}'
	encoding = 'iiii iiii iiii iiii'

class Disassembler:
	def __init__(self, filename, args):
		self.mc = mc = Microcode(path=filename)
		if args.output:
			output = open(args.output, 'w+')
		else:
			output = sys.stdout
		print(f'.type {mc.mc_type}', file=output)
		print(f'.version {mc.version} ; {filename}', file=output)
		print(f'.sram_addr 0x{mc.sram_addr:04x}', file=output)
		if not args.disassemble:
			return
		self.seg_duration = 0
		self.address_to_label = {}
		if args.labels:
			for line in open(args.labels, 'r'):
				address, label = line.rstrip('\n').split(' ')
				self.address_to_label[int(address, 16)] = label
		lines = []
		self.call_xrefs = set()
		self.jump_xrefs = set()
		for i in range(0, len(mc.code), 4):
			address = i // 4
			if self.seg_duration == 0:
				self.segment = address >> 13
			else:
				self.seg_duration -= 1
			word = struct.unpack('>I', mc.code[i:i+4])[0] & 0xFFFF
			opcode, operands = self.instruction(word)
			asm = (opcode.ljust(10) + operands).ljust(29)
			lines.append(f'\t{asm} ; {address:04x}: 0x{word:04x} ({word>>12&15:04b} {word>>8&15:04b} {word>>4&15:04b} {word&15:04b})')
			#lines.append(f'\t{asm} ; 0x{word:04x} ({word>>12&15:04b} {word>>8&15:04b} {word>>4&15:04b} {word&15:04b})')
			# hack to make segmented addressing work,
			# in reality the segment is probably just state that gets pushed onto the call stack
			if opcode == 'seg':
				self.segment = (word >> 1) & 1
				self.seg_duration = 2
			elif opcode == 'call':
				self.seg_duration = 0
		for i, line in enumerate(lines):
			if i in self.call_xrefs:
				print(self.label('fun', i) + ':', file=output)
			if i in self.jump_xrefs:
				print(self.label('loc', i) + ':', file=output)
			print(line, file=output)
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
		with open(path, 'rb') as f:
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
	parser.add_argument('filename', nargs='+')
	parser.add_argument('-o', '--output')
	parser.add_argument('-l', '--labels')
	parser.add_argument('-a', '--assemble', action='store_true')
	parser.add_argument('-d', '--disassemble', action='store_true')
	parser.add_argument('--diff', action='store_true')
	args = parser.parse_args()
	for filename in args.filename:
		if args.assemble:
			Assembler(filename, args)
		else:
			Disassembler(filename, args)
