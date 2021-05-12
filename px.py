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
class wait_load: # 3cy, used to wait for loads
	operands = ''
	encoding = '0000 0000 1000 0000'

@instruction
class wait_other: # 5cy, used to wait for register writes (e.g. to use getdcr)
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
class push: # push to stack (overwriting the oldest entry on overflow), needs one wait state before ret works
	operands = 'r{src}'
	encoding = '0000 0011 0000 0sss'
	def emulate(state, src):
		state.call_stack[state.stack_ptr] = state.main_reg[src]
		state.stack_ptr = (state.stack_ptr + 1) & 31

@instruction
class emit_lo:
	operands = 'r{reg}'
	encoding = '0000 0101 0000 0rrr'

@instruction
class emit_hi:
	operands = 'r{reg}'
	encoding = '0000 0110 0000 0rrr'

@instruction
class emit:
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
		result = state.main_reg[lhs] + state.main_regs[rhs]
		state.carry_flag = result > 0xFFFF
		state.main_reg[dst] = result & 0xFFFF

@instruction
class sub: # subtraction (set carry on signed overflow)
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '0.10 0ddd 11rr rlll'
	def emulate(state, dst, lhs, rhs):
		result = state.main_reg[lhs] + (~state.main_regs[rhs] & 0xFFFF) + 1
		state.carry_flag = result >> 16
		state.main_reg[dst] = result & 0xFFFF

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
class load: # read SRAM
	operands = 'r{dst}, r{src}'
	encoding = '0010 1ddd 1011 0sss'
	def emulate(state, dst, src):
		tmp = state.main_reg[src]
		result = tmp + 1
		state.carry_flag = result >> 16
		state.main_reg[src] = result & 0xFFFF
		state.main_reg[dst] = state.memory[tmp]

@instruction
class addc:
	operands = 'r{dst}, r{src}'
	encoding = '1.10 1ddd 1011 0sss'
	def emulate(state, dst, src):
		result = state.main_reg[src] + state.carry_flag
		state.carry_flag = result >> 16
		state.main_reg[dst] = result & 0xFFFF

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
class sa: # store A temp register to GPR (16 bits)
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
class getdcr: # 1cy, read direct communication register
	# after writing the DCR, it takes 4 cycles until the new value can be read
	operands = 'r{dst}'
	# lowest three bits are ignored
	encoding = '0.10 1ddd 1111 1000'
	def emulate(state, dst):
		state.main_reg[dst] = (state.hw_reg[7] << 8) | state.hw_reg[8]

@instruction
class getcore:
	operands = 'r{dst}'
	encoding = '1.10 1ddd 1111 1000'
	def emulate(state, dst):
		state.main_reg[dst] = state.core_id
@instruction
class pop: # pop item from stack or zero if stack is empty
	operands = 'r{dst}'
	encoding = '1.10 1ddd 1111 1001'
	def emulate(state, dst):
		state.stack_ptr = (state.stack_ptr - 1) & 31
		state.main_reg[dst] = state.call_stack[state.stack_ptr]
		state.call_stack[state.stack_ptr] = 0

@instruction
class setreg: # 1cy, load lower 8 bits from GPR into accelerator register
	operands = '0x{imm4:x}, r{src}'
	encoding = '0100 0000 0iii isss'
	def emulate(state, dst, src):
		state.hw_reg[dst] = state.main_reg[src] & 0xFF

@instruction
class setregi: # load 8-bit immediate into accelerator register
	operands = '0x{imm4:x}, 0x{jmm8:02x} ; {jmm8}'
	encoding = '1i00 0jjj jjjj jiii'
	def emulate(state, dst, imm8):
		state.hw_reg[dst] = imm8

@instruction
class lis: # load immediate shifted (flags are set according to the whole 16-bit register)
	operands = 'r{dst}, 0x{imm8:02x} ; {imm8}'
	encoding = '1.00 1iii iiii iddd'
	def emulate(state, dst, imm8):
		state.main_reg[dst] = (imm8 << 8) | (state.main_regs[dst] & 0xFF)

@instruction
class andi: # bitwise and with 3-bit immediate
	operands = 'r{dst}, r{lhs}, {imm3_minus_one}'
	encoding = '1.10 0ddd 00ii illl'
	def emulate(state, dst, lhs, imm3_minus_one):
		state.main_reg[dst] = state.main_reg[lhs] & imm3_minus_one

@instruction
class store: # write SRAM (4096 bytes)
	operands = 'r{dst}, r{lhs}, r{rhs}'
	encoding = '1.10 0ddd 01rr rlll'
	def emulate(state, dst, lhs, rhs):
		state.memory[state.main_reg[lhs] & 0x7FF] = state.main_reg[rhs]
		result = state.main_reg[lhs] + 1
		state.carry_flag = result >> 16
		state.main_reg[dst] = result & 0xFFFF

@instruction
class addi: # add 3-bit immediate (set carry on unsigned overflow)
	operands = 'r{dst}, r{lhs}, {imm3_minus_one}'
	encoding = '1.10 0ddd 10ii illl'
	def emulate(state, dst, lhs, imm3_minus_one):
		result = state.main_reg[lhs] + imm3_minus_one
		state.carry_flag = result > 0xFFFF
		state.main_reg[dst] = result & 0xFFFF

@instruction
class subi: # subtract 3-bit immediate (set carry on signed overflow)
	operands = 'r{dst}, r{lhs}, {imm3_minus_one}'
	encoding = '1.10 0ddd 11ii illl'
	def emulate(state, dst, lhs, imm3_minus_one):
		result = state.main_reg[lhs] + (~imm3_minus_one & 0xFFFF) + 1
		state.carry_flag = result >> 16
		state.main_reg[dst] = result & 0xFFFF

#@instruction
#class dw:
#	operands = '0x{imm16:04x}'
#	encoding = 'iiii iiii iiii iiii'
