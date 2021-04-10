#!/usr/bin/env python3

from nitrox import instruction

@instruction
class nop: # 1cy
	operands = ''
	encoding = '0000 0000 0000 0000'
	def emulate():
		pass

@instruction
class seg: # 1cy
	operands = '{seg}'
	encoding = '0000 0000 0000 0ss1'
	def emulate(state, segment):
		state.segment = segment

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
class call: # call + ret: 6-8cy
	operands = '{addr_}'
	encoding = 'aa11 1aaa aaaa aaaa'
	def emulate(state, addr):
		assert len(state.call_stack) < 32
		state.call_stack.append(state.pc)
		state.pc = (state.segment << 13) | addr

@instruction
class ret: # call + ret 0: 6cy, call + ret 1: 8cy
	operands = '{imm1}'
	encoding = '0000 0010 i000 0000'
	def emulate(state, imm1): # TODO: what does imm1 do?
		state.pc = state.call_stack.pop()
		state.segment = state.pc >> 13

@instruction
class op0300: # TODO 1cy
	operands = 'r{reg}'
	encoding = '0000 0011 0000 0rrr'

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
	operands = '0x{imm8:02x} ; {imm8}'
	encoding = '0000 0111 iiii iiii'

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
class input: # read high-level operation (1cy but sometimes hangs)
	operands = 'r{dst}, r{src}'
	encoding = '0010 1ddd 1011 0sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = state.memory[state.main_reg[src]]
		state.main_reg[src] += 1
		raise NotImplementedError

@instruction
class inc: # FIXME: doesn't always increment
	operands = 'r{dst}, r{src}'
	encoding = '1.10 1ddd 1011 0sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = state.main_reg[src] + 1

@instruction
class align8: # 1cy
	operands = 'r{dst}, r{src}'
	encoding = '0.10 1ddd 1011 1sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = (state.main_reg[src] + 7) & (-7 & 0xFFFF)

@instruction
class align16: # 1cy
	operands = 'r{dst}, r{src}'
	encoding = '1.10 1ddd 1011 1sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = (state.main_reg[src] + 15) & (-15 & 0xFFFF)

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
class align4:
	operands = 'r{dst}, r{src}'
	encoding = '1.10 1ddd 1111 0sss'
	def emulate(state, dst, src):
		state.main_reg[dst] = (state.main_reg[src] + 3) & (-3 & 0xFFFF)

@instruction
class op28f8: # TODO (1cy)
	# dst is definitely a GPR
	# always writes 0x0006 (operation code?)
	# the '.' is correct
	operands = 'r{dst}, a{src}'
	encoding = '0.10 1ddd 1111 1sss'

@instruction
class opa8f8: # TODO (1cy)
	# dst is definitely a GPR
	# the '.' is correct
	# a0 reads core ID, a1 reads random stuff
	operands = 'r{dst}, a{src}'
	encoding = '1.10 1ddd 1111 1sss'

@instruction
class op4000: # TODO (1cy)
	# src is definitely a GPR
	# imm4=3 fucks up SHA1 hashes (didn't test other hashes)
	# imm4=a stalls the next op4000 for 122 cycles (!)
	# 4/5: read or write pointer?
	# c/d: read or write pointer?
	operands = '0x{imm4:x}, r{src}'
	encoding = '0100 0000 0iii isss'

@instruction
class op8000: # TODO
	# jmm is definitely an immediate (at least 8 bits)
	# op4000 and op8000 are the same thing, just GPR operand vs immediate operand
	# (compare CNPx-MC-SSL-MAIN-0022:0e84 and CNPx-MC-SSL-MAIN-0026:0c59)
	operands = '0x{imm4:x}, 0x{jmm8:02x} ; {jmm8}'
	encoding = '1i00 0jjj jjjj jiii'

#@instruction
#class opc000: # TODO
#	operands = 'r{reg}, 0x{imm8:02x} ; {imm8}'
#	encoding = '1100 0iii iiii irrr'

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
class output:
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '1.10 0ddd 01rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.memory[state.main_reg[lhs]] = state.main_reg[rhs]
		state.main_reg[dst] = state.main_reg[lhs] + 1

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
