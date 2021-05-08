#!/usr/bin/env python3

from nitrox import instruction

@instruction
class nop: # 1cy
	operands = ''
	encoding = '0000 0000 0000 0000'
	def emulate():
		pass

@instruction
class emit_lo:
	operands = 'r{reg}'
	encoding = '0000 0000 0010 0rrr'

@instruction
class emit_hi:
	operands = 'r{reg}'
	encoding = '0000 0000 0100 0rrr'

@instruction
class wait_other: # 5cy
	operands = ''
	encoding = '1000 0010 0000 0000'

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
class call: # call + ret: 6-8cy
	operands = '{addr_}'
	encoding = 'aa11 1aaa aaaa aaaa'
	def emulate(state, addr):
		assert len(state.call_stack) < 32
		state.call_stack.append(state.pc)
		state.pc = (state.segment << 13) | addr

@instruction
class ret:
	operands = '{imm1}'
	encoding = 'i000 0001 0000 0000'

@instruction
class emit:
	operands = '0x{imm8:02x}'
	encoding = '^000 0100 iiii iiii'

@instruction
class li: # load immediate (1cy)
	operands = 'r{dst}, 0x{imm8:02x} ; {imm8}'
	encoding = '0.00 1ddd iiii iiii'
	def emulate(state, dst, imm8):
		state.main_reg[dst] = imm8

@instruction
class and_: # bitwise and (1cy)
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '^.10 0ddd 00rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] & state.main_regs[rhs]

@instruction
class or_: # bitwise or (1cy)
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '^.10 0ddd 01rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] | state.main_regs[rhs]

@instruction
class add: # addition (1cy)
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '^.10 0ddd 10rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] + state.main_regs[rhs]

@instruction
class sub: # subtraction (1cy)
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '^.10 0ddd 11rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.main_reg[dst] = state.main_reg[lhs] - state.main_regs[rhs]

@instruction
class shl3: # shift left by 3 (1cy)
	operands = 'r{dst}, r{lhs}'
	encoding = '^.10 1ddd 0001 0lll'
	def emulate(state, dst, lhs):
		state.main_reg[dst] = (state.main_reg[lhs] << 3) & 0xFFFF

@instruction
class shr3: # logical shift right by 3 (1cy)
	operands = 'r{dst}, r{lhs}'
	encoding = '^.10 1ddd 0010 0lll'
	def emulate(state, dst, lhs):
		state.main_reg[dst] = state.main_reg[lhs] >> 3

@instruction
class shr1: # logical shift right by 1 (1cy)
	operands = 'r{dst}, r{lhs}'
	encoding = '^.10 1ddd 0011 0lll'
	def emulate(state, dst, lhs):
		state.main_reg[dst] = state.main_reg[lhs] >> 1

@instruction
class not_:
	operands = 'r{dst}, r{src}'
	encoding = '^.10 1ddd 0100 0sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = ~state.main_reg[src] & 0xFFFF

@instruction
class getdcr:
	operands = 'r{dst}'
	encoding = '^.10 1ddd 0101 0000'

@instruction
class getcore:
	operands = 'r{dst}'
	encoding = '^.10 1ddd 0110 0000'

@instruction
class la:
	operands = 'a{dst}, r{src}'
	encoding = '^010 1ddd 1000 0sss'
	def emulate(state, dst, src):
		state.temp_reg[dst] = state.main_reg[src]

@instruction
class lb:
	operands = 'b{dst}, r{src}'
	encoding = '^010 1ddd 1000 1sss'
	def emulate(state, dst, src):
		state.temp_reg[dst] = state.main_reg[src]

@instruction
class la_hi:
	operands = 'a{dst}, r{src}'
	encoding = '^010 1ddd 1001 0sss'
	def emulate(state, dst, src):
		state.addr_reg[dst] &= 0xFF
		state.addr_reg[dst] |= (state.main_reg[src] & 0xFF) << 8

@instruction
class lb_hi:
	operands = 'b{dst}, r{src}'
	encoding = '^010 1ddd 1001 1sss'
	def emulate(state, dst, src):
		state.addr_reg[dst] &= 0xFF
		state.addr_reg[dst] |= (state.main_reg[src] & 0xFF) << 8
@instruction
class la_lo:
	operands = 'a{dst}, r{src}'
	encoding = '^010 1ddd 1010 0sss'
	def emulate(state, dst, src):
		state.addr_reg[dst] &= 0xFF00
		state.addr_reg[dst] |= state.main_reg[src] & 0xFF

@instruction
class lb_lo:
	operands = 'b{dst}, r{src}'
	encoding = '^010 1ddd 1010 1sss'
	def emulate(state, dst, src):
		state.tmp_reg[dst+8] &= 0xFF00
		state.tmp_reg[dst+8] |= state.main_reg[src] & 0xFF

@instruction
class sa:
	operands = 'r{dst}, a{src}'
	encoding = '^.10 1ddd 1100 0sss'

@instruction
class sb:
	operands = 'r{dst}, b{src}'
	encoding = '^.10 1ddd 1100 1sss'

@instruction
class sa_hi:
	operands = 'r{dst}, a{src}'
	encoding = '^.10 1ddd 1101 0sss'

@instruction
class sb_hi:
	operands = 'r{dst}, b{src}'
	encoding = '^.10 1ddd 1101 1sss'

@instruction
class sa_lo:
	operands = 'r{dst}, a{src}'
	encoding = '^.10 1ddd 1110 0sss'

@instruction
class sb_lo:
	operands = 'r{dst}, b{src}'
	encoding = '^.10 1ddd 1110 1sss'
