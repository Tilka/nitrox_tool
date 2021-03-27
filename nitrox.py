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

@instruction
class nop: # 1cy
	operands = ''
	encoding = '0000 0000 0000 0000'
	def emulate():
		pass

@instruction
class seg: # 1cy
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
class wait_input: # 3cy
	operands = ''
	encoding = '0000 0000 1000 0000'

@instruction
class wait_other: # 5cy
	operands = ''
	encoding = '0000 0001 1000 0000'

@instruction
class jz: # taken: 5cy, not taken: 1cy
	operands = '{addr}'
	encoding = 'aa11 0aaa aaaa aaaa'
	def emulate(state, addr):
		if state.result == 0:
			state.pc = (state.segment << 13) | addr

@instruction
class jnz: # same latencies as jz
	operands = '{addr}'
	encoding = 'aa01 0aaa aaaa aaaa'
	def emulate(state, addr):
		if state.result != 0:
			state.pc = (state.segment << 13) | addr

@instruction
class js: # same latencies as jz
	operands = '{addr}'
	encoding = 'aa01 1aaa aaaa aaaa'
	def emulate(state, addr):
		if state.result & 0x8000:
			state.pc = (state.segment << 13) | addr

@instruction
class call: # call + ret_px: 6-8cy
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
class ret_px: # call + ret_px 0: 6cy, call + ret_px 1: 8cy
	operands = '{imm1}'
	encoding = '0000 0010 i000 0000'
	def emulate(state, imm1): # TODO: what does imm1 do?
		state.pc = state.call_stack.pop()
		state.segment = state.pc >> 13

@instruction
class op0300: # TODO 1cy
	operands = 'r{reg}'
	encoding = '^000 0011 0000 0rrr'

@instruction
class op0400: # TODO (lite)
	operands = '0x{imm8:02x}'
	encoding = '0000 0100 iiii iiii'

@instruction
class op0500: # TODO
	operands = 'r{reg}'
	encoding = '0000 0101 0000 0rrr'

@instruction
class op0600: # TODO 1cy
	operands = 'r{reg}'
	encoding = '0000 0110 0000 0rrr'

@instruction
class op0700: # TODO 1cy
	operands = '0x{imm8:02x}'
	encoding = '^000 0111 iiii iiii'

@instruction
class li: # load immediate (1cy)
	operands = 'r{dst}, 0x{imm8:02x} ; {imm8}'
	encoding = '0.00 1ddd iiii iiii'
	def emulate(state, dst, imm8):
		state.main_reg[dst] = imm8

@instruction
class and_: # bitwise and (1cy)
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0.10 0ddd 00rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] & state.main_regs[rhs]

@instruction
class or_: # bitwise or (1cy)
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0.10 0ddd 01rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] | state.main_regs[rhs]

@instruction
class add: # addition (1cy)
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0.10 0ddd 10rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] + state.main_regs[rhs]

@instruction
class sub: # subtraction (1cy)
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0.10 0ddd 11rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] - state.main_regs[rhs]

@instruction
class shli: # shift left by immediate (1cy)
	operands = 'r{dst}, r{lhs}, {imm4}'
	encoding = 'i.10 1ddd 00ii illl'
	def emulate(state, dst, lhs, imm4):
		state.main_reg[dst] = (state.main_reg[lhs] << imm4) & 0xFFFF

@instruction
class shri: # logical shift right by immediate (1cy)
	operands = 'r{dst}, r{lhs}, {imm4}'
	encoding = 'i.10 1ddd 01ii illl'
	def emulate(state, dst, lhs, imm4):
		state.main_reg[dst] = state.main_reg[lhs] >> imm4

@instruction
class la: # load A temp register (16 bits, 1cy)
	operands = 'a{dst}, r{src}'
	encoding = '0010 1ddd 1000 0sss'
	def emulate(state, dst, src):
		state.temp_reg[dst] = state.main_reg[src]

@instruction
class lb: # load B temp register (16 bits, 1cy)
	operands = 'b{dst}, r{src}'
	encoding = '0010 1ddd 1000 1sss'
	def emulate(state, dst, src):
		state.temp_reg[dst] = state.main_reg[src]

@instruction
class lc: # load C temp register (16 bits, 1cy)
	operands = 'c{dst}, r{src}'
	encoding = '1010 1ddd 1000 0sss'
	def emulate(state, dst, src):
		state.temp_reg[dst] = state.main_reg[src]

@instruction
class ld: # load D temp register (16 bits, 1cy)
	operands = 'd{dst}, r{src}'
	encoding = '1010 1ddd 1000 1sss'
	def emulate(state, dst, src):
		state.temp_reg[dst] = state.main_reg[src]

@instruction
class la_hi: # load A temp register (high 8 bits)
	operands = 'a{dst}, r{src}'
	encoding = '0010 1ddd 1001 0sss'
	def emulate(state, dst, src):
		state.addr_reg[dst] &= 0xFF
		state.addr_reg[dst] |= (state.main_reg[src] & 0xFF) << 8

@instruction
class lb_hi: # load B temp register (high 8 bits)
	operands = 'b{dst}, r{src}'
	encoding = '0010 1ddd 1001 1sss'
	def emulate(state, dst, src):
		state.addr_reg[dst] &= 0xFF
		state.addr_reg[dst] |= (state.main_reg[src] & 0xFF) << 8

@instruction
class lc_hi: # load C temp register (high 8 bits)
	operands = 'c{dst}, r{src}'
	encoding = '1010 1ddd 1001 0sss'
	def emulate(state, dst, src):
		state.addr_reg[dst] &= 0xFF
		state.addr_reg[dst] |= (state.main_reg[src] & 0xFF) << 8

@instruction
class ld_hi: # load D temp register (high 8 bits)
	operands = 'd{dst}, r{src}'
	encoding = '1010 1ddd 1001 1sss'
	def emulate(state, dst, src):
		state.addr_reg[dst] &= 0xFF
		state.addr_reg[dst] |= (state.main_reg[src] & 0xFF) << 8

@instruction
class la_lo: # load A temp register (low 8 bits)
	operands = 'a{dst}, r{src}'
	encoding = '0010 1ddd 1010 0sss'
	def emulate(state, dst, src):
		state.addr_reg[dst] &= 0xFF00
		state.addr_reg[dst] |= state.main_reg[src] & 0xFF

@instruction
class lb_lo: # load B temp register (low 8 bits)
	operands = 'b{dst}, r{src}'
	encoding = '0010 1ddd 1010 1sss'
	def emulate(state, dst, src):
		state.tmp_reg[dst+8] &= 0xFF00
		state.tmp_reg[dst+8] |= state.main_reg[src] & 0xFF

@instruction
class lc_lo: # load C temp register (low 8 bits)
	operands = 'c{dst}, r{src}'
	encoding = '1010 1ddd 1010 0sss'
	def emulate(state, dst, src):
		state.tmp_reg[dst+16] &= 0xFF00
		state.tmp_reg[dst+16] |= state.main_reg[src] & 0xFF

@instruction
class ld_lo: # load D temp register (low 8 bits)
	operands = 'd{dst}, r{src}'
	encoding = '1010 1ddd 1010 1sss'
	def emulate(state, dst, src):
		state.tmp_reg[dst+24] &= 0xFF00
		state.tmp_reg[dst+24] |= state.main_reg[src] & 0xFF

@instruction
class input: # read high-level operation (1cy but sometimes hangs), TODO: what does it do for offsets higher than 32?
	operands = 'r{dst}, r{src}'
	encoding = '^010 1ddd 1011 0sss'
	def emulate(state, dst, src):
		# main_reg[src] is an offset
		raise NotImplementedError

@instruction
class align8: # 1cy
	operands = 'r{dst}, r{src}'
	encoding = '0.10 1ddd 1011 1sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = (state.main_reg[src] + 7) & -7

@instruction
class align16: # 1cy
	operands = 'r{dst}, r{src}'
	encoding = '1.10 1ddd 1011 1sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = (state.main_reg[src] + 15) & -15

@instruction
class sa: # store address register to GPR (16 bits)
	operands = 'r{dst}, a{src}'
	encoding = '0.10 1ddd 1100 0sss'

@instruction
class sb:
	operands = 'r{dst}, b{src}'
	encoding = '0.10 1ddd 1100 1sss'

@instruction
class sc:
	operands = 'r{dst}, c{src}'
	encoding = '1.10 1ddd 1100 0sss'

@instruction
class sd:
	operands = 'r{dst}, d{src}'
	encoding = '1.10 1ddd 1100 1sss'

@instruction
class sa_hi:
	operands = 'r{dst}, a{src}'
	encoding = '0.10 1ddd 1101 0sss'

@instruction
class sb_hi:
	operands = 'r{dst}, b{src}'
	encoding = '0.10 1ddd 1101 1sss'

@instruction
class sc_hi:
	operands = 'r{dst}, c{src}'
	encoding = '1.10 1ddd 1101 0sss'

@instruction
class sd_hi:
	operands = 'r{dst}, d{src}'
	encoding = '1.10 1ddd 1101 1sss'

@instruction
class sa_lo:
	operands = 'r{dst}, a{src}'
	encoding = '0.10 1ddd 1110 0sss'

@instruction
class sb_lo:
	operands = 'r{dst}, b{src}'
	encoding = '0.10 1ddd 1110 1sss'

@instruction
class sc_lo:
	operands = 'r{dst}, c{src}'
	encoding = '1.10 1ddd 1110 0sss'

@instruction
class sd_lo:
	operands = 'r{dst}, d{src}'
	encoding = '1.10 1ddd 1110 1sss'

@instruction
class not_:
	operands = 'r{dst}, r{src}'
	encoding = '0.10 1ddd 1111 0sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = ~state.main_reg[src] & 0xFFFF

@instruction
class op28f8: # TODO (1cy)
	# dst is definitely a GPR
	# always writes 0x0006 (operation code?)
	# the '.' is correct
	# the '^' might be a different opcode (a1 reads random stuff)
	operands = 'r{dst}, a{src}'
	encoding = '^.10 1ddd 1111 1sss'

@instruction
class op4000: # TODO (1cy)
	# src is definitely a GPR
	# imm4=3 fucks up SHA1 hashes (didn't test other hashes)
	# imm4=a stalls the next op4000 for 122 cycles (!)
	operands = '0x{imm4:x}, r{src}'
	encoding = '0100 0000 0iii isss'

@instruction
class op8000: # TODO
	operands = '0x{imm8:02x}, r{reg} ; {imm8}'
	encoding = '1000 0iii iiii irrr'

@instruction
class opc000: # TODO
	operands = '0x{imm8:02x}, r{reg} ; {imm8}'
	encoding = '1100 0iii iiii irrr'

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
	operands = 'a{dst}, r{lhs}, r{rhs}'
	encoding = '1010 0ddd 01rr rlll'

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
#class dw:
#	operands = '0x{imm16:04x}'
#	encoding = 'iiii iiii iiii iiii'

class Disassembler:
	def __init__(self, filename, args):
		self.mc = mc = Microcode(path=filename, raw=args.raw)
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
		for i in range(0, len(mc.code), 4):
			address = i // 4
			if self.seg_duration > 0:
				self.seg_duration -= 1
			elif not args.diff:
				self.segment = address >> 13
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
	def __init__(self, path=None, raw=False):
		if path is not None:
			self.load(path, raw)
		else:
			self.init_empty()

	def init_empty(self):
		self.mc_type = 1
		self.version = 'undefined'
		self.sram_addr = 0
		self.code = []
		self.data = b''
		self.signature = b''

	def load(self, path, raw):
		with open(path, 'rb') as f:
			d = f.read()
		if raw:
			self.init_empty()
			self.code = d
			return
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
	parser.add_argument('--stat', action='store_true')
	parser.add_argument('--diff', action='store_true')
	parser.add_argument('--raw', action='store_true')
	args = parser.parse_args()
	for filename in args.filename:
		if args.assemble:
			Assembler(filename, args)
		else:
			Disassembler(filename, args)
