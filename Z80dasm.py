# -*- coding: utf-8 -*-
# Copyright (c) 2023 Hirokuni Yano
#
# Released under the MIT license.
# see https://opensource.org/licenses/MIT
#
# Reference:
# * The Undocumented Z80 Documented
#   Sean Young, Version 0.91, 18th September, 2005
#

class Bus:
    def __init__(self, read, write):
        self.read = read
        self.write = write

class Z80dasm:
    # attributes bitmap
    A_ANALYZED  = 0x01
    A_CODE      = 0x02
    A_BYTE      = 0x04
    A_WORD      = 0x08
    A_JP_TABLE  = 0x10
    A_DT_TABLE  = 0x20
    A_LABEL     = 0x40
    A_NO_LABEL  = 0x80

    # Constructor
    def __init__(self, bus, fn_print):
        self.bus = bus
        self.print = fn_print

        self.m_output = False
        self.attr = [0] * 0x10000
        self.datalen = [1] * 0x10000
        self.datawidth = [0] * 0x10000
        self.comment = [[] for _ in range(0x10000)]

        self.m_label_prefix = "L"
        self.m_comment_prefix = "; "
        self.m_config_patch = False

        self.m_start_addr = 0x00000
        self.m_end_addr   = 0x10000
        self.m_entry_addr = 0x00000

        self.initialize_mnemonics()
        self.initialize_tables()

    def config_label_prefix(self, prefix):
        self.m_label_prefix = prefix

    def config_enable_patch(self, enable):
        self.m_config_patch = enable

    def is_valid_addr(self, addr):
        return (addr >= self.m_start_addr) and (addr < self.m_end_addr)

    # Check attributes

    def is_analyzed(self, addr):
        return (self.attr[addr] & self.A_ANALYZED) != 0

    def is_code(self, addr):
        return (self.attr[addr] & self.A_CODE) != 0

    def is_byte(self, addr):
        return (self.attr[addr] & self.A_BYTE) != 0

    def is_word(self, addr):
        return (self.attr[addr] & self.A_WORD) != 0

    def is_jp_table(self, addr):
        return (self.attr[addr] & self.A_JP_TABLE) != 0

    def is_dt_table(self, addr):
        return (self.attr[addr] & self.A_DT_TABLE) != 0

    def is_label(self, addr):
        return (self.attr[addr] & self.A_LABEL) != 0

    def is_no_label(self, addr):
        return (self.attr[addr] & self.A_NO_LABEL) != 0

    def is_defined(self, addr):
        if self.is_code(addr): return True
        if self.is_byte(addr): return True
        if self.is_word(addr): return True
        if self.is_jp_table(addr): return True
        if self.is_dt_table(addr): return True
        return False

    # Set attributes

    def set_analyzed(self, addr):
        self.attr[addr] |= self.A_ANALYZED

    def set_code(self, addr):
        if not self.is_defined(addr):
            self.attr[addr] |= self.A_CODE

    def set_byte(self, addr, count, width = 16):
        self.attr[addr] |= self.A_BYTE
        self.datalen[addr] = count
        self.datawidth[addr] = width
        self.set_label(addr + count)

    def set_word(self, addr, count, width = 16):
        self.attr[addr] |= self.A_WORD
        self.datalen[addr] = count
        self.datawidth[addr] = width
        self.set_label(addr + count * 2)

    def set_jp_table(self, addr, count):
        self.attr[addr] |= self.A_JP_TABLE
        self.datalen[addr] = count
        for i in range(count):
            a = self.rm16(addr)
            self.set_label(a)
            self.set_code(a)
            addr += 2
        self.set_label(addr)

    def set_dt_table(self, addr, count):
        self.attr[addr] |= self.A_DT_TABLE
        self.datalen[addr] = count
        for i in range(count):
            a = self.rm16(addr)
            self.set_label(a)
            addr += 2
        self.set_label(addr)

    def set_label(self, addr):
        if not self.is_valid_addr(addr): return
        if not self.is_no_label(addr):
            self.attr[addr] |= self.A_LABEL

    def set_no_label(self, addr):
        self.attr[addr] |= self.A_NO_LABEL
        self.attr[addr] &= ~self.A_LABEL

    def add_comment(self, addr, comment):
        self.comment[addr].append(f"{self.m_comment_prefix}{comment:s}")

    def add_patch(self, addr, patch):
        if self.m_config_patch:
            self.comment[addr].append(f"{patch:s}")

    def next_label(self, addr, step = 1):
        while addr < self.m_end_addr and not self.is_label(addr):
            addr += step
        return addr

    def stop(self, b):
        self.m_stop = b

    def is_stopped(self):
        return self.m_stop

    # for DD/FD prefix

    def reg_n(self):
        self.m_reg8 = self.m_reg8n
        self.m_reg16 = self.m_reg16n
        self.m_reg16a = self.m_reg16an

    def reg_ix(self):
        self.m_reg8 = self.m_reg8x
        self.m_reg16 = self.m_reg16x
        self.m_reg16a = self.m_reg16ax

    def reg_iy(self):
        self.m_reg8 = self.m_reg8y
        self.m_reg16 = self.m_reg16y
        self.m_reg16a = self.m_reg16ay

    # Analyze an instruction

    def exec(self, op_table, opcode):
        self.m_opcode = opcode
        op_table[opcode]()

    # Disassemble

    def disassemble(self, start_addr, end_addr, entry_addr):
        self.m_start_addr = start_addr
        self.m_end_addr = end_addr
        self.m_entry_addr = entry_addr

        self.set_code(self.m_entry_addr)
        self.set_label(self.m_entry_addr)

        # Pass 1
        self.m_output = False
        while True:
            for addr in range(self.m_start_addr, self.m_end_addr):
                if (not self.is_analyzed(addr) and self.is_code(addr)):
                    break
            else:
                break

            self.m_pc = addr
            self.stop(False)
            while True:
                if self.is_stopped():
                    break
                if self.m_pc >= self.m_end_addr:
                    break

                self.reg_n()
                opcode = self.rop()
                self.exec(self.op_op, opcode)

        # define unknown block as byte
        for addr in range(self.m_start_addr, self.m_end_addr):
            if self.is_label(addr) and not self.is_defined(addr):
                top = addr
                addr += 1
                while addr < self.m_end_addr:
                    if self.is_label(addr) or self.is_defined(addr):
                        break
                    addr += 1
                self.set_byte(top, addr - top)

        # Pass 2
        self.m_output = True
        self.m_pc = self.m_start_addr
        while self.m_pc < self.m_end_addr:
            addr = self.m_pc

            self.output_comment(addr)

            if self.is_label(addr):
                self.p(f"{self.str_l(addr)}:")

            if self.is_code(addr):
                self.reg_n()
                opcode = self.rop()
                self.exec(self.op_op, opcode)
            elif self.is_byte(addr):
                count = self.datalen[addr]
                width = self.datawidth[addr]
                if count == 0:
                    next_addr = self.next_label(addr + 1)
                    count = next_addr - addr
                self.dump_byte("${:02x}", count, width)
            elif self.is_word(addr):
                count = self.datalen[addr]
                width = self.datawidth[addr]
                if count == 0:
                    next_addr = self.next_label(addr + 2 , 2)
                    count = next_addr - addr
                self.dump_word("${:04x}", count, width)
            elif self.is_jp_table(addr):
                count = self.datalen[addr]
                self.dump_word(f"{self.m_label_prefix}{{:04x}}", count)
            elif self.is_dt_table(addr):
                count = self.datalen[addr]
                self.dump_word(f"{self.m_label_prefix}{{:04x}}", count)
            else:
                self.p(f"\tdb\t${self.rop():02x}")

    # Label file processing

    def label_command(self, line):
        l = line.split(" ")
        cmd = l[0]
        if (cmd == 'c'):
            addr = int(l[1], 16)
            self.set_code(addr)
            self.set_label(addr)
        elif (cmd == 'b'):
            addr = int(l[1], 16)
            count = int(l[2], 16)
            if len(l) >= 4:
                width = int(l[3], 16)
                self.set_byte(addr, count, width)
            else:
                self.set_byte(addr, count)
            self.set_label(addr)
        elif (cmd == 'w'):
            addr = int(l[1], 16)
            count = int(l[2], 16)
            if len(l) >= 4:
                width = int(l[3], 16)
            else:
                self.set_word(addr, count)
            self.set_label(addr)
        elif (cmd == 't'):
            addr = int(l[1], 16)
            count = int(l[2], 16)
            self.set_jp_table(addr, count)
            self.set_label(addr)
        elif (cmd == 'u'):
            addr = int(l[1], 16)
            count = int(l[2], 16)
            self.set_dt_table(addr, count)
            self.set_label(addr)
        elif (cmd == 'l'):
            addr = int(l[1], 16)
            self.set_label(addr)
        elif (cmd == 'n'):
            addr = int(l[1], 16)
            self.set_no_label(addr)
        
        elif (cmd == 'r'):
            addr = int(l[1], 16)
            comment = " ".join(l[2:])
            self.add_comment(addr, comment)
        elif (cmd == 'p'):
            addr = int(l[1], 16)
            patch = " ".join(l[2:])
            self.add_patch(addr, patch)

    # Output

    def p(self, str, end="\n"):
        if self.m_output:
            self.print(str, end=end)

    def str_s8(self, value):
        if value >= 0:
            return f"+{value:02x}h"
        else:
            return f"-{-value:02x}h"

    def str_l(self, addr):
        return f"{self.m_label_prefix}{addr:04x}"

    def dump_byte(self, msg, count, width=16):
        while count > 0:
            self.p("\tdb\t", end = "")
            for i in range(width):
                if i != 0:
                    self.p(", ", end="")
                self.p(msg.format(self.arg()), end="")
                count -= 1
                if count == 0:
                    break
            self.p("")

    def dump_word(self, msg, count, width=8):
        while count > 0:
            self.p("\tdw\t", end = "")
            for i in range(width):
                if i != 0:
                    self.p(", ", end="")
                self.p(msg.format(self.arg16()), end="")
                count -= 1
                if count == 0:
                    break
            self.p("")

    def output_comment(self, addr):
        for comment in self.comment[addr]:
            self.p(comment)

    # Memory access

    def rm(self, addr):
        res = self.bus.read(addr)
        return res

    def rm16(self, addr):
        res = self.bus.read(addr)
        return (self.rm(addr + 1) << 8) | res

    def rop(self):
        self.set_analyzed(self.m_pc)
        self.set_code(self.m_pc)
        res = self.rm(self.m_pc)
        self.m_pc += 1
        return res

    def arg(self):
        arg = self.rm(self.m_pc)
        self.m_pc += 1
        return arg

    def arg16(self):
        res = self.arg()
        return (self.arg() << 8) | res

    def ridx(self):
        self.m_idx = self.s8[self.arg()]

    # definition of instructions

    # 8-Bit Load Group

    def ld_r_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 3) & 0x07
        r1 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tld\t{reg[r0]:s},{reg[r1]:s}")

    def ld_r_n(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 3) & 0x07
        n = self.arg()
        self.p(f"\tld\t{reg[r0]:s},${n:02x}")
    
    def ld_r_pxy(self):
        reg = self.m_reg8n
        r0 = (self.m_opcode >> 3) & 0x07
        r1 = 2
        o = self.arg()
        self.p(f"\tld\t{reg[r0]:s},({self.m_reg16[r1]:s}{self.str_s8(o):s})")

    def ld_pxy_r(self):
        reg = self.m_reg8n
        r0 = 2
        r1 = (self.m_opcode >> 0) & 0x07
        o = self.arg()
        self.p(f"\tld\t({self.m_reg16[r0]:s}{self.str_s8(o):s}),{reg[r1]:s}")

    def ld_pxy_n(self):
        reg = self.m_reg16
        r0 = 2
        o = self.arg()
        n = self.arg()
        self.p(f"\tld\t({reg[r0]:s}{self.str_s8(o):s}),${n:02x}")

    def ld_a_pbc(self):
        self.p("\tld\ta,(bc)")

    def ld_a_pde(self):
        self.p("\tld\ta,(de)")

    def ld_a_pnn(self):
        addr = self.arg16()
        self.set_label(addr)
        self.p(f"\tld\ta,({self.str_l(addr)})")

    def ld_pbc_a(self):
        self.p("\tld\t(bc),a")

    def ld_pde_a(self):
        self.p("\tld\t(de),a")

    def ld_pnn_a(self):
        addr = self.arg16()
        self.set_label(addr)
        self.p(f"\tld\t({self.str_l(addr)}),a")

    def ld_a_i(self):
        self.p("\tld\ta,i")

    def ld_a_r(self):
        self.p("\tld\ta,r")

    def ld_i_a(self):
        self.p("\tld\ti,a")

    def ld_r_a(self):
        self.p("\tld\tr,a")

    # 16-Bit Load Group

    def ld_dd_nn(self):
        reg = self.m_reg16
        r0 = (self.m_opcode >> 4) & 0x03
        nn = self.arg16()
        self.set_label(nn)
        self.p(f"\tld\t{reg[r0]:s},${nn:04x}")

    def ld_hl_pnn(self):
        addr = self.arg16()
        self.set_label(addr)
        self.p(f"\tld\thl,({self.str_l(addr)})")

    def ld_dd_pnn(self):
        reg = self.m_reg16
        r0 = (self.m_opcode >> 4) & 0x03
        addr = self.arg16()
        self.set_label(addr)
        self.p(f"\tld\t{reg[r0]:s},({self.str_l(addr)})")

    def ld_pnn_hl(self):
        addr = self.arg16()
        self.set_label(addr)
        self.p(f"\tld\t({self.str_l(addr)}),hl")

    def ld_pnn_dd(self):
        reg = self.m_reg16
        r0 = (self.m_opcode >> 4) & 0x03
        addr = self.arg16()
        self.set_label(addr)
        self.p(f"\tld\t({self.str_l(addr)},{reg[r0]:s}")

    def ld_sp_hl(self):
        self.p("\tld\tsp,hl")

    def push_qq(self):
        reg = self.m_reg16a
        r0 = (self.m_opcode >> 4) & 0x03
        self.p(f"\tpush\t{reg[r0]:s}")

    def pop_qq(self):
        reg = self.m_reg16a
        r0 = (self.m_opcode >> 4) & 0x03
        self.p(f"\tpop\t{reg[r0]:s}")

    # Exchange, Block Transfer, Search Group

    def ex_de_hl(self):
        self.p("\tex\tde,hl")

    def ex_af_af(self):
        self.p("\tex\taf,af'")

    def exx(self):
        self.p("\texx")

    def ex_psp_hl(self):
        self.p("\tex\t(sp),hl")

    def ldi(self):
        self.p("\tldi")

    def ldir(self):
        self.p("\tldir")

    def ldd(self):
        self.p("\tldd")

    def lddr(self):
        self.p("\tlddr")

    def cpi(self):
        self.p("\tcpi")

    def cpir(self):
        self.p("\tcpir")

    def cpd(self):
        self.p("\tcpd")

    def cpdr(self):
        self.p("\tcpdr")

    # 8-Bit Arithmetic and Logical Group

    def add_a_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tadd\ta,{reg[r0]:s}")

    def add_a_n(self):
        n = self.arg()
        self.p(f"\tadd\ta,${n:02x}")

    def add_a_pxy(self):
        reg = self.m_reg16
        r0 = 2
        o = self.arg()
        self.p(f"\tadd\ta,({reg[r0]:s}{self.str_s8(o):s})")

    def adc_a_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tadc\ta,{reg[r0]:s}")

    def adc_a_n(self):
        n = self.arg()
        self.p(f"\tadc\ta,${n:02x}")

    def adc_a_pxy(self):
        reg = self.m_reg16
        r0 = 2
        o = self.arg()
        self.p(f"\tadc\ta,({reg[r0]:s}{self.str_s8(o):s})")

    def sub_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tsub\t{reg[r0]:s}")

    def sub_n(self):
        n = self.arg()
        self.p(f"\tsub\t${n:02x}")

    def sub_pxy(self):
        reg = self.m_reg16
        r0 = 2
        o = self.arg()
        self.p(f"\tsub\t({reg[r0]:s}{self.str_s8(o):s})")

    def sbc_a_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tsbc\ta,{reg[r0]:s}")

    def sbc_a_n(self):
        n = self.arg()
        self.p(f"\tsbc\ta,${n:02x}")

    def sbc_a_pxy(self):
        reg = self.m_reg16
        r0 = 2
        o = self.arg()
        self.p(f"\tsbc\ta,({reg[r0]:s}{self.str_s8(o):s})")

    def and_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tand\t{reg[r0]:s}")

    def and_n(self):
        n = self.arg()
        self.p(f"\tand\t${n:02x}")

    def and_pxy(self):
        reg = self.m_reg16
        r0 = 2
        o = self.arg()
        self.p(f"\tand\t({reg[r0]:s}{self.str_s8(o):s})")

    def or_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tor\t{reg[r0]:s}")

    def or_n(self):
        n = self.arg()
        self.p(f"\tor\t${n:02x}")

    def or_pxy(self):
        reg = self.m_reg16
        r0 = 2
        o = self.arg()
        self.p(f"\tor\t({reg[r0]:s}{self.str_s8(o):s})")

    def xor_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\txor\t{reg[r0]:s}")

    def xor_n(self):
        n = self.arg()
        self.p(f"\txor\t${n:02x}")

    def xor_pxy(self):
        reg = self.m_reg16
        r0 = 2
        o = self.arg()
        self.p(f"\txor\ta,({reg[r0]:s}{self.str_s8(o):s})")

    def cp_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tcp\t{reg[r0]:s}")

    def cp_n(self):
        n = self.arg()
        self.p(f"\tcp\t${n:02x}")

    def cp_pxy(self):
        reg = self.m_reg16
        r0 = 2
        o = self.arg()
        self.p(f"\tcp\t({reg[r0]:s}{self.str_s8(o):s})")

    def inc_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 3) & 0x07
        self.p(f"\tinc\t{reg[r0]:s}")

    def inc_pxy(self):
        reg = self.m_reg16
        r0 = 2
        o = self.arg()
        self.p(f"\tinc\t({reg[r0]:s}{self.str_s8(o):s})")

    def dec_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 3) & 0x07
        self.p(f"\tdec\t{reg[r0]:s}")

    def dec_pxy(self):
        reg = self.m_reg16
        r0 = 2
        o = self.arg()
        self.p(f"\tdec\t({reg[r0]:s}{self.str_s8(o):s})")

    # General-Purpose Arithmetic and CPU Control Group

    def daa(self):
        self.p("\tdaa")

    def cpl(self):
        self.p("\tcpl")

    def neg(self):
        self.p("\tneg")

    def ccf(self):
        self.p("\tccf")

    def scf(self):
        self.p("\tscf")

    def nop(self):
        self.p("\tnop")

    def halt(self):
        self.p("\thalt")

    def di(self):
        self.p("\tdi")

    def ei(self):
        self.p("\tei")

    def im_0(self):
        self.p("\tim\t0")

    def im_1(self):
        self.p("\tim\t1")

    def im_2(self):
        self.p("\tim\t2")

    # 16-Bit Arithmetic Group

    def add_hl_ss(self):
        reg = self.m_reg16
        r0 = (self.m_opcode >> 4) & 0x03
        self.p(f"\tadd\thl,{reg[r0]:s}")

    def adc_hl_ss(self):
        reg = self.m_reg16
        r0 = (self.m_opcode >> 4) & 0x03
        self.p(f"\tadc\thl,{reg[r0]:s}")

    def sbc_hl_ss(self):
        reg = self.m_reg16
        r0 = (self.m_opcode >> 4) & 0x03
        self.p(f"\tsbc\thl,{reg[r0]:s}")

    def inc_ss(self):
        reg = self.m_reg16
        r0 = (self.m_opcode >> 4) & 0x03
        self.p(f"\tinc\t{reg[r0]:s}")

    def dec_ss(self):
        reg = self.m_reg16
        r0 = (self.m_opcode >> 4) & 0x03
        self.p(f"\tdec\t{reg[r0]:s}")

    # Rotate and Shift Group

    def rlca(self):
        self.p("\trlca")

    def rla(self):
        self.p("\trla")

    def rrca(self):
        self.p("\trrca")

    def rra(self):
        self.p("\trra")

    def rlc_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\trlc\t{reg[r0]:s}")
    
    def rlc_pxy(self):
        r0 = 2
        o = self.m_idx
        self.p(f"\trlc\t({self.m_reg16[r0]:s}{self.str_s8(o):s})")

    def rlc_pxy_r(self):
        reg = self.m_reg8n
        r0 = 2
        r1 = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\trlc\t({self.m_reg16[r0]:s}{self.str_s8(o):s}),{reg[r1]:s}")

    def rl_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\trl\t{reg[r0]:s}")

    def rl_pxy(self):
        r0 = 2
        o = self.m_idx
        self.p(f"\trl\t({self.m_reg16[r0]:s}{self.str_s8(o):s})")

    def rl_pxy_r(self):
        reg = self.m_reg8n
        r0 = 2
        r1 = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\trl\t({self.m_reg16[r0]:s}{self.str_s8(o):s}),{reg[r1]:s}")

    def rrc_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\trrc\t{reg[r0]:s}")

    def rrc_pxy(self):
        r0 = 2
        o = self.m_idx
        self.p(f"\trrc\t({self.m_reg16[r0]:s}{self.str_s8(o):s})")

    def rrc_pxy_r(self):
        reg = self.m_reg8n
        r0 = 2
        r1 = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\trrc\t({self.m_reg16[r0]:s}{self.str_s8(o):s}),{reg[r1]:s}")

    def rr_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\trr\t{reg[r0]:s}")

    def rr_pxy(self):
        r0 = 2
        o = self.m_idx
        self.p(f"\trr\t({self.m_reg16[r0]:s}{self.str_s8(o):s})")

    def rr_pxy_r(self):
        reg = self.m_reg8n
        r0 = 2
        r1 = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\trr\t({self.m_reg16[r0]:s}{self.str_s8(o):s}),{reg[r1]:s}")

    def sla_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tsla\t{reg[r0]:s}")

    def sla_pxy(self):
        r0 = 2
        o = self.m_idx
        self.p(f"\tsla\t({self.m_reg16[r0]:s}{self.str_s8(o):s})")

    def sla_pxy_r(self):
        reg = self.m_reg8n
        r0 = 2
        r1 = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\tsla\t({self.m_reg16[r0]:s}{self.str_s8(o):s}),{reg[r1]:s}")

    def sll_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tsll\t{reg[r0]:s}")

    def sll_pxy(self):
        r0 = 2
        o = self.m_idx
        self.p(f"\tsll\t({self.m_reg16[r0]:s}{self.str_s8(o):s})")

    def sll_pxy_r(self):
        reg = self.m_reg8n
        r0 = 2
        r1 = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\tsll\t({self.m_reg16[r0]:s}{self.str_s8(o):s}),{reg[r1]:s}")

    def sra_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tsra\t{reg[r0]:s}")

    def sra_pxy(self):
        r0 = 2
        o = self.m_idx
        self.p(f"\tsra\t({self.m_reg16[r0]:s}{self.str_s8(o):s})")

    def sra_pxy_r(self):
        reg = self.m_reg8n
        r0 = 2
        r1 = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\tsra\t({self.m_reg16[r0]:s}{self.str_s8(o):s}),{reg[r1]:s}")

    def srl_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        self.p(f"\tsrl\t{reg[r0]:s}")

    def srl_pxy(self):
        r0 = 2
        o = self.m_idx
        self.p(f"\tsrl\t({self.m_reg16[r0]:s}{self.str_s8(o):s})")

    def srl_pxy_r(self):
        reg = self.m_reg8n
        r0 = 2
        r1 = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\tsrl\t({self.m_reg16[r0]:s}{self.str_s8(o):s}),{reg[r1]:s}")

    def rld(self):
        self.p("\trld")

    def rrd(self):
        self.p("\trrd")

    # Bit Set, Reset and Test Group

    def bit_b_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        b = (self.m_opcode >> 3) & 0x07
        self.p(f"\tbit\t{b:d},{reg[r0]:s}")

    def bit_pxy(self):
        r0 = 2
        b = (self.m_opcode >> 3) & 0x07
        o = self.m_idx
        self.p(f"\tbit\t{b:d},({self.m_reg16[r0]:s}{self.str_s8(o):s})")

    def set_b_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        b = (self.m_opcode >> 3) & 0x07
        self.p(f"\tset\t{b:d},{reg[r0]:s}")

    def set_pxy(self):
        r0 = 2
        b = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\tset\t{b:d},({self.m_reg16[r0]:s}{self.str_s8(o):s})")

    def set_pxy_r(self):
        reg = self.m_reg8n
        r0 = 2
        b = (self.m_opcode >> 3) & 0x07
        r1 = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\tset\t{b:d},({self.m_reg16[r0]:s}{self.str_s8(o):s}),{reg[r1]:s}")

    def res_b_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 0) & 0x07
        b = (self.m_opcode >> 3) & 0x07
        self.p(f"\tres\t{b:d},{reg[r0]:s}")

    def res_pxy(self):
        r0 = 2
        b = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\tres\t{b:d},({self.m_reg16[r0]:s}{self.str_s8(o):s})")

    def res_pxy_r(self):
        reg = self.m_reg8n
        r0 = 2
        b = (self.m_opcode >> 3) & 0x07
        r1 = (self.m_opcode >> 0) & 0x07
        o = self.m_idx
        self.p(f"\tres\t{b:d},({self.m_reg16[r0]:s}{self.str_s8(o):s}),{reg[r1]:s}")

    # Jump Group

    def jp_nn(self):
        addr = self.arg16()
        self.set_label(addr)
        self.set_code(addr)
        self.p(f"\tjp\t{self.str_l(addr)}")
        self.set_label(self.m_pc)
        self.stop(True)

    def jp_cc_nn(self):
        cc = (self.m_opcode >> 3) & 0x07
        addr = self.arg16()
        self.set_label(addr)
        self.set_code(addr)
        self.p(f"\tjp\t{self.m_cc[cc]:s},{self.str_l(addr)}")

    def jr_e(self):
        offset = self.s8[self.arg()]
        addr = self.m_pc + offset
        self.set_label(addr)
        self.set_code(addr)
        self.p(f"\tjr\t{self.str_l(addr)}")
        self.set_label(self.m_pc)
        self.stop(True)

    def jr_ss_e(self):
        cc = (self.m_opcode >> 3) & 0x03
        offset = self.s8[self.arg()]
        addr = self.m_pc + offset
        self.set_label(addr)
        self.set_code(addr)
        self.p(f"\tjr\t{self.m_cc[cc]:s},{self.str_l(addr)}")

    def jp_phl(self):
        self.p("\tjp\t(hl)")
        self.set_label(self.m_pc)
        self.stop(True)

    def djnz_e(self):
        offset = self.s8[self.arg()]
        addr = self.m_pc + offset
        self.set_label(addr)
        self.set_code(addr)
        self.p(f"\tdjnz\t{self.str_l(addr)}")

    # Call and Return Group

    def call_nn(self):
        addr = self.arg16()
        self.set_label(addr)
        self.set_code(addr)
        self.p(f"\tcall\t{self.str_l(addr)}")

    def call_cc_nn(self):
        cc = (self.m_opcode >> 3) & 0x07
        addr = self.arg16()
        self.set_label(addr)
        self.set_code(addr)
        self.p(f"\tcall\t{self.m_cc[cc]:s},{self.str_l(addr)}")

    def ret(self):
        self.p("\tret")
        self.set_label(self.m_pc)
        self.stop(True)

    def ret_cc(self):
        cc = (self.m_opcode >> 3) & 0x07
        self.p(f"\tret\t{self.m_cc[cc]:s}")

    def reti(self):
        self.p("\treti")
        self.set_label(self.m_pc)
        self.stop(True)

    def retn(self):
        self.p("\tretn")
        self.set_label(self.m_pc)
        self.stop(True)

    def rst_p(self):
        addr = self.m_opcode & 0x38
        self.set_label(addr)
        self.set_code(addr)
        self.p(f"\trst\t{addr:02x}h")

    # Input and Output Group
    def in_a_pn(self):
        n = self.arg()
        self.p(f"\tin\ta,(${n:02x})")

    def in_r_pc(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 3) & 0x07
        self.p(f"\tin\t{reg[r0]:s},(c)")

    def in_f_pc(self):
        self.p("\tin\tf,(c)")

    def ini(self):
        self.p("\tini")

    def inir(self):
        self.p("\tinir")

    def ind(self):
        self.p("\tind")

    def indr(self):
        self.p("\tindr")

    def out_pn_a(self):
        n = self.arg()
        self.p(f"\tout\t(${n:02x}),a")

    def out_pc_r(self):
        reg = self.m_reg8
        r0 = (self.m_opcode >> 3) & 0x07
        self.p(f"\tout\t(c),{reg[r0]:s}")

    def out_pc_0(self):
        self.p("\tout\t(c),0")

    def outi(self):
        self.p("\touti")

    def otir(self):
        self.p("\totir")

    def outd(self):
        self.p("\toutd")

    def otdr(self):
        self.p("\totdr")

    # Illegal opcode

    def illegal(self, num):
        self.p(f"* ILLEGAL OPCODE: {self.m_pc - num:04x}")
        self.stop(True)

    # opcodes with CB prefix
    # rotate, shift and bit operations
    def op_cb_00(self): self.rlc_r()
    def op_cb_01(self): self.rlc_r()
    def op_cb_02(self): self.rlc_r()
    def op_cb_03(self): self.rlc_r()
    def op_cb_04(self): self.rlc_r()
    def op_cb_05(self): self.rlc_r()
    def op_cb_06(self): self.rlc_r()
    def op_cb_07(self): self.rlc_r()

    def op_cb_08(self): self.rrc_r()
    def op_cb_09(self): self.rrc_r()
    def op_cb_0a(self): self.rrc_r()
    def op_cb_0b(self): self.rrc_r()
    def op_cb_0c(self): self.rrc_r()
    def op_cb_0d(self): self.rrc_r()
    def op_cb_0e(self): self.rrc_r()
    def op_cb_0f(self): self.rrc_r()

    def op_cb_10(self): self.rl_r()
    def op_cb_11(self): self.rl_r()
    def op_cb_12(self): self.rl_r()
    def op_cb_13(self): self.rl_r()
    def op_cb_14(self): self.rl_r()
    def op_cb_15(self): self.rl_r()
    def op_cb_16(self): self.rl_r()
    def op_cb_17(self): self.rl_r()

    def op_cb_18(self): self.rr_r()
    def op_cb_19(self): self.rr_r()
    def op_cb_1a(self): self.rr_r()
    def op_cb_1b(self): self.rr_r()
    def op_cb_1c(self): self.rr_r()
    def op_cb_1d(self): self.rr_r()
    def op_cb_1e(self): self.rr_r()
    def op_cb_1f(self): self.rr_r()

    def op_cb_20(self): self.sla_r()
    def op_cb_21(self): self.sla_r()
    def op_cb_22(self): self.sla_r()
    def op_cb_23(self): self.sla_r()
    def op_cb_24(self): self.sla_r()
    def op_cb_25(self): self.sla_r()
    def op_cb_26(self): self.sla_r()
    def op_cb_27(self): self.sla_r()

    def op_cb_28(self): self.sra_r()
    def op_cb_29(self): self.sra_r()
    def op_cb_2a(self): self.sra_r()
    def op_cb_2b(self): self.sra_r()
    def op_cb_2c(self): self.sra_r()
    def op_cb_2d(self): self.sra_r()
    def op_cb_2e(self): self.sra_r()
    def op_cb_2f(self): self.sra_r()

    def op_cb_30(self): self.sll_r()
    def op_cb_31(self): self.sll_r()
    def op_cb_32(self): self.sll_r()
    def op_cb_33(self): self.sll_r()
    def op_cb_34(self): self.sll_r()
    def op_cb_35(self): self.sll_r()
    def op_cb_36(self): self.sll_r()
    def op_cb_37(self): self.sll_r()

    def op_cb_38(self): self.srl_r()
    def op_cb_39(self): self.srl_r()
    def op_cb_3a(self): self.srl_r()
    def op_cb_3b(self): self.srl_r()
    def op_cb_3c(self): self.srl_r()
    def op_cb_3d(self): self.srl_r()
    def op_cb_3e(self): self.srl_r()
    def op_cb_3f(self): self.srl_r()

    def op_cb_40(self): self.bit_b_r()
    def op_cb_41(self): self.bit_b_r()
    def op_cb_42(self): self.bit_b_r()
    def op_cb_43(self): self.bit_b_r()
    def op_cb_44(self): self.bit_b_r()
    def op_cb_45(self): self.bit_b_r()
    def op_cb_46(self): self.bit_b_r()
    def op_cb_47(self): self.bit_b_r()

    def op_cb_48(self): self.bit_b_r()
    def op_cb_49(self): self.bit_b_r()
    def op_cb_4a(self): self.bit_b_r()
    def op_cb_4b(self): self.bit_b_r()
    def op_cb_4c(self): self.bit_b_r()
    def op_cb_4d(self): self.bit_b_r()
    def op_cb_4e(self): self.bit_b_r()
    def op_cb_4f(self): self.bit_b_r()

    def op_cb_50(self): self.bit_b_r()
    def op_cb_51(self): self.bit_b_r()
    def op_cb_52(self): self.bit_b_r()
    def op_cb_53(self): self.bit_b_r()
    def op_cb_54(self): self.bit_b_r()
    def op_cb_55(self): self.bit_b_r()
    def op_cb_56(self): self.bit_b_r()
    def op_cb_57(self): self.bit_b_r()

    def op_cb_58(self): self.bit_b_r()
    def op_cb_59(self): self.bit_b_r()
    def op_cb_5a(self): self.bit_b_r()
    def op_cb_5b(self): self.bit_b_r()
    def op_cb_5c(self): self.bit_b_r()
    def op_cb_5d(self): self.bit_b_r()
    def op_cb_5e(self): self.bit_b_r()
    def op_cb_5f(self): self.bit_b_r()

    def op_cb_60(self): self.bit_b_r()
    def op_cb_61(self): self.bit_b_r()
    def op_cb_62(self): self.bit_b_r()
    def op_cb_63(self): self.bit_b_r()
    def op_cb_64(self): self.bit_b_r()
    def op_cb_65(self): self.bit_b_r()
    def op_cb_66(self): self.bit_b_r()
    def op_cb_67(self): self.bit_b_r()

    def op_cb_68(self): self.bit_b_r()
    def op_cb_69(self): self.bit_b_r()
    def op_cb_6a(self): self.bit_b_r()
    def op_cb_6b(self): self.bit_b_r()
    def op_cb_6c(self): self.bit_b_r()
    def op_cb_6d(self): self.bit_b_r()
    def op_cb_6e(self): self.bit_b_r()
    def op_cb_6f(self): self.bit_b_r()

    def op_cb_70(self): self.bit_b_r()
    def op_cb_71(self): self.bit_b_r()
    def op_cb_72(self): self.bit_b_r()
    def op_cb_73(self): self.bit_b_r()
    def op_cb_74(self): self.bit_b_r()
    def op_cb_75(self): self.bit_b_r()
    def op_cb_76(self): self.bit_b_r()
    def op_cb_77(self): self.bit_b_r()

    def op_cb_78(self): self.bit_b_r()
    def op_cb_79(self): self.bit_b_r()
    def op_cb_7a(self): self.bit_b_r()
    def op_cb_7b(self): self.bit_b_r()
    def op_cb_7c(self): self.bit_b_r()
    def op_cb_7d(self): self.bit_b_r()
    def op_cb_7e(self): self.bit_b_r()
    def op_cb_7f(self): self.bit_b_r()

    def op_cb_80(self): self.res_b_r()
    def op_cb_81(self): self.res_b_r()
    def op_cb_82(self): self.res_b_r()
    def op_cb_83(self): self.res_b_r()
    def op_cb_84(self): self.res_b_r()
    def op_cb_85(self): self.res_b_r()
    def op_cb_86(self): self.res_b_r()
    def op_cb_87(self): self.res_b_r()

    def op_cb_88(self): self.res_b_r()
    def op_cb_89(self): self.res_b_r()
    def op_cb_8a(self): self.res_b_r()
    def op_cb_8b(self): self.res_b_r()
    def op_cb_8c(self): self.res_b_r()
    def op_cb_8d(self): self.res_b_r()
    def op_cb_8e(self): self.res_b_r()
    def op_cb_8f(self): self.res_b_r()

    def op_cb_90(self): self.res_b_r()
    def op_cb_91(self): self.res_b_r()
    def op_cb_92(self): self.res_b_r()
    def op_cb_93(self): self.res_b_r()
    def op_cb_94(self): self.res_b_r()
    def op_cb_95(self): self.res_b_r()
    def op_cb_96(self): self.res_b_r()
    def op_cb_97(self): self.res_b_r()

    def op_cb_98(self): self.res_b_r()
    def op_cb_99(self): self.res_b_r()
    def op_cb_9a(self): self.res_b_r()
    def op_cb_9b(self): self.res_b_r()
    def op_cb_9c(self): self.res_b_r()
    def op_cb_9d(self): self.res_b_r()
    def op_cb_9e(self): self.res_b_r()
    def op_cb_9f(self): self.res_b_r()

    def op_cb_a0(self): self.res_b_r()
    def op_cb_a1(self): self.res_b_r()
    def op_cb_a2(self): self.res_b_r()
    def op_cb_a3(self): self.res_b_r()
    def op_cb_a4(self): self.res_b_r()
    def op_cb_a5(self): self.res_b_r()
    def op_cb_a6(self): self.res_b_r()
    def op_cb_a7(self): self.res_b_r()

    def op_cb_a8(self): self.res_b_r()
    def op_cb_a9(self): self.res_b_r()
    def op_cb_aa(self): self.res_b_r()
    def op_cb_ab(self): self.res_b_r()
    def op_cb_ac(self): self.res_b_r()
    def op_cb_ad(self): self.res_b_r()
    def op_cb_ae(self): self.res_b_r()
    def op_cb_af(self): self.res_b_r()

    def op_cb_b0(self): self.res_b_r()
    def op_cb_b1(self): self.res_b_r()
    def op_cb_b2(self): self.res_b_r()
    def op_cb_b3(self): self.res_b_r()
    def op_cb_b4(self): self.res_b_r()
    def op_cb_b5(self): self.res_b_r()
    def op_cb_b6(self): self.res_b_r()
    def op_cb_b7(self): self.res_b_r()

    def op_cb_b8(self): self.res_b_r()
    def op_cb_b9(self): self.res_b_r()
    def op_cb_ba(self): self.res_b_r()
    def op_cb_bb(self): self.res_b_r()
    def op_cb_bc(self): self.res_b_r()
    def op_cb_bd(self): self.res_b_r()
    def op_cb_be(self): self.res_b_r()
    def op_cb_bf(self): self.res_b_r()

    def op_cb_c0(self): self.set_b_r()
    def op_cb_c1(self): self.set_b_r()
    def op_cb_c2(self): self.set_b_r()
    def op_cb_c3(self): self.set_b_r()
    def op_cb_c4(self): self.set_b_r()
    def op_cb_c5(self): self.set_b_r()
    def op_cb_c6(self): self.set_b_r()
    def op_cb_c7(self): self.set_b_r()

    def op_cb_c8(self): self.set_b_r()
    def op_cb_c9(self): self.set_b_r()
    def op_cb_ca(self): self.set_b_r()
    def op_cb_cb(self): self.set_b_r()
    def op_cb_cc(self): self.set_b_r()
    def op_cb_cd(self): self.set_b_r()
    def op_cb_ce(self): self.set_b_r()
    def op_cb_cf(self): self.set_b_r()

    def op_cb_d0(self): self.set_b_r()
    def op_cb_d1(self): self.set_b_r()
    def op_cb_d2(self): self.set_b_r()
    def op_cb_d3(self): self.set_b_r()
    def op_cb_d4(self): self.set_b_r()
    def op_cb_d5(self): self.set_b_r()
    def op_cb_d6(self): self.set_b_r()
    def op_cb_d7(self): self.set_b_r()

    def op_cb_d8(self): self.set_b_r()
    def op_cb_d9(self): self.set_b_r()
    def op_cb_da(self): self.set_b_r()
    def op_cb_db(self): self.set_b_r()
    def op_cb_dc(self): self.set_b_r()
    def op_cb_dd(self): self.set_b_r()
    def op_cb_de(self): self.set_b_r()
    def op_cb_df(self): self.set_b_r()

    def op_cb_e0(self): self.set_b_r()
    def op_cb_e1(self): self.set_b_r()
    def op_cb_e2(self): self.set_b_r()
    def op_cb_e3(self): self.set_b_r()
    def op_cb_e4(self): self.set_b_r()
    def op_cb_e5(self): self.set_b_r()
    def op_cb_e6(self): self.set_b_r()
    def op_cb_e7(self): self.set_b_r()

    def op_cb_e8(self): self.set_b_r()
    def op_cb_e9(self): self.set_b_r()
    def op_cb_ea(self): self.set_b_r()
    def op_cb_eb(self): self.set_b_r()
    def op_cb_ec(self): self.set_b_r()
    def op_cb_ed(self): self.set_b_r()
    def op_cb_ee(self): self.set_b_r()
    def op_cb_ef(self): self.set_b_r()

    def op_cb_f0(self): self.set_b_r()
    def op_cb_f1(self): self.set_b_r()
    def op_cb_f2(self): self.set_b_r()
    def op_cb_f3(self): self.set_b_r()
    def op_cb_f4(self): self.set_b_r()
    def op_cb_f5(self): self.set_b_r()
    def op_cb_f6(self): self.set_b_r()
    def op_cb_f7(self): self.set_b_r()

    def op_cb_f8(self): self.set_b_r()
    def op_cb_f9(self): self.set_b_r()
    def op_cb_fa(self): self.set_b_r()
    def op_cb_fb(self): self.set_b_r()
    def op_cb_fc(self): self.set_b_r()
    def op_cb_fd(self): self.set_b_r()
    def op_cb_fe(self): self.set_b_r()
    def op_cb_ff(self): self.set_b_r()

    # opcodes with DD/FD CB prefix
    # rotate, shift and bit operations with (IX+o)
    def op_xycb_00(self): self.rlc_pxy_r()
    def op_xycb_01(self): self.rlc_pxy_r()
    def op_xycb_02(self): self.rlc_pxy_r()
    def op_xycb_03(self): self.rlc_pxy_r()
    def op_xycb_04(self): self.rlc_pxy_r()
    def op_xycb_05(self): self.rlc_pxy_r()
    def op_xycb_06(self): self.rlc_pxy()
    def op_xycb_07(self): self.rlc_pxy_r()

    def op_xycb_08(self): self.rrc_pxy_r()
    def op_xycb_09(self): self.rrc_pxy_r()
    def op_xycb_0a(self): self.rrc_pxy_r()
    def op_xycb_0b(self): self.rrc_pxy_r()
    def op_xycb_0c(self): self.rrc_pxy_r()
    def op_xycb_0d(self): self.rrc_pxy_r()
    def op_xycb_0e(self): self.rrc_pxy()
    def op_xycb_0f(self): self.rrc_pxy_r()

    def op_xycb_10(self): self.rl_pxy_r()
    def op_xycb_11(self): self.rl_pxy_r()
    def op_xycb_12(self): self.rl_pxy_r()
    def op_xycb_13(self): self.rl_pxy_r()
    def op_xycb_14(self): self.rl_pxy_r()
    def op_xycb_15(self): self.rl_pxy_r()
    def op_xycb_16(self): self.rl_pxy()
    def op_xycb_17(self): self.rl_pxy_r()

    def op_xycb_18(self): self.rr_pxy_r()
    def op_xycb_19(self): self.rr_pxy_r()
    def op_xycb_1a(self): self.rr_pxy_r()
    def op_xycb_1b(self): self.rr_pxy_r()
    def op_xycb_1c(self): self.rr_pxy_r()
    def op_xycb_1d(self): self.rr_pxy_r()
    def op_xycb_1e(self): self.rr_pxy()
    def op_xycb_1f(self): self.rr_pxy_r()

    def op_xycb_20(self): self.sla_pxy_r()
    def op_xycb_21(self): self.sla_pxy_r()
    def op_xycb_22(self): self.sla_pxy_r()
    def op_xycb_23(self): self.sla_pxy_r()
    def op_xycb_24(self): self.sla_pxy_r()
    def op_xycb_25(self): self.sla_pxy_r()
    def op_xycb_26(self): self.sla_pxy()
    def op_xycb_27(self): self.sla_pxy_r()

    def op_xycb_28(self): self.sra_pxy_r()
    def op_xycb_29(self): self.sra_pxy_r()
    def op_xycb_2a(self): self.sra_pxy_r()
    def op_xycb_2b(self): self.sra_pxy_r()
    def op_xycb_2c(self): self.sra_pxy_r()
    def op_xycb_2d(self): self.sra_pxy_r()
    def op_xycb_2e(self): self.sra_pxy()
    def op_xycb_2f(self): self.sra_pxy_r()

    def op_xycb_30(self): self.sll_pxy_r()
    def op_xycb_31(self): self.sll_pxy_r()
    def op_xycb_32(self): self.sll_pxy_r()
    def op_xycb_33(self): self.sll_pxy_r()
    def op_xycb_34(self): self.sll_pxy_r()
    def op_xycb_35(self): self.sll_pxy_r()
    def op_xycb_36(self): self.sll_pxy()
    def op_xycb_37(self): self.sll_pxy_r()

    def op_xycb_38(self): self.srl_pxy_r()
    def op_xycb_39(self): self.srl_pxy_r()
    def op_xycb_3a(self): self.srl_pxy_r()
    def op_xycb_3b(self): self.srl_pxy_r()
    def op_xycb_3c(self): self.srl_pxy_r()
    def op_xycb_3d(self): self.srl_pxy_r()
    def op_xycb_3e(self): self.srl_pxy()
    def op_xycb_3f(self): self.srl_pxy_r()

    def op_xycb_40(self): self.op_xycb_46()
    def op_xycb_41(self): self.op_xycb_46()
    def op_xycb_42(self): self.op_xycb_46()
    def op_xycb_43(self): self.op_xycb_46()
    def op_xycb_44(self): self.op_xycb_46()
    def op_xycb_45(self): self.op_xycb_46()
    def op_xycb_46(self): self.bit_pxy()
    def op_xycb_47(self): self.op_xycb_46()

    def op_xycb_48(self): self.op_xycb_4e()
    def op_xycb_49(self): self.op_xycb_4e()
    def op_xycb_4a(self): self.op_xycb_4e()
    def op_xycb_4b(self): self.op_xycb_4e()
    def op_xycb_4c(self): self.op_xycb_4e()
    def op_xycb_4d(self): self.op_xycb_4e()
    def op_xycb_4e(self): self.bit_pxy()
    def op_xycb_4f(self): self.op_xycb_4e()

    def op_xycb_50(self): self.op_xycb_56()
    def op_xycb_51(self): self.op_xycb_56()
    def op_xycb_52(self): self.op_xycb_56()
    def op_xycb_53(self): self.op_xycb_56()
    def op_xycb_54(self): self.op_xycb_56()
    def op_xycb_55(self): self.op_xycb_56()
    def op_xycb_56(self): self.bit_pxy()
    def op_xycb_57(self): self.op_xycb_56()

    def op_xycb_58(self): self.op_xycb_5e()
    def op_xycb_59(self): self.op_xycb_5e()
    def op_xycb_5a(self): self.op_xycb_5e()
    def op_xycb_5b(self): self.op_xycb_5e()
    def op_xycb_5c(self): self.op_xycb_5e()
    def op_xycb_5d(self): self.op_xycb_5e()
    def op_xycb_5e(self): self.bit_pxy()
    def op_xycb_5f(self): self.op_xycb_5e()

    def op_xycb_60(self): self.op_xycb_66()
    def op_xycb_61(self): self.op_xycb_66()
    def op_xycb_62(self): self.op_xycb_66()
    def op_xycb_63(self): self.op_xycb_66()
    def op_xycb_64(self): self.op_xycb_66()
    def op_xycb_65(self): self.op_xycb_66()
    def op_xycb_66(self): self.bit_pxy()
    def op_xycb_67(self): self.op_xycb_66()

    def op_xycb_68(self): self.op_xycb_6e()
    def op_xycb_69(self): self.op_xycb_6e()
    def op_xycb_6a(self): self.op_xycb_6e()
    def op_xycb_6b(self): self.op_xycb_6e()
    def op_xycb_6c(self): self.op_xycb_6e()
    def op_xycb_6d(self): self.op_xycb_6e()
    def op_xycb_6e(self): self.bit_pxy()
    def op_xycb_6f(self): self.op_xycb_6e()

    def op_xycb_70(self): self.op_xycb_76()
    def op_xycb_71(self): self.op_xycb_76()
    def op_xycb_72(self): self.op_xycb_76()
    def op_xycb_73(self): self.op_xycb_76()
    def op_xycb_74(self): self.op_xycb_76()
    def op_xycb_75(self): self.op_xycb_76()
    def op_xycb_76(self): self.bit_pxy()
    def op_xycb_77(self): self.op_xycb_76()

    def op_xycb_78(self): self.op_xycb_7e()
    def op_xycb_79(self): self.op_xycb_7e()
    def op_xycb_7a(self): self.op_xycb_7e()
    def op_xycb_7b(self): self.op_xycb_7e()
    def op_xycb_7c(self): self.op_xycb_7e()
    def op_xycb_7d(self): self.op_xycb_7e()
    def op_xycb_7e(self): self.bit_pxy()
    def op_xycb_7f(self): self.op_xycb_7e()

    def op_xycb_80(self): self.res_pxy_r()
    def op_xycb_81(self): self.res_pxy_r()
    def op_xycb_82(self): self.res_pxy_r()
    def op_xycb_83(self): self.res_pxy_r()
    def op_xycb_84(self): self.res_pxy_r()
    def op_xycb_85(self): self.res_pxy_r()
    def op_xycb_86(self): self.res_pxy()
    def op_xycb_87(self): self.res_pxy_r()

    def op_xycb_88(self): self.res_pxy_r()
    def op_xycb_89(self): self.res_pxy_r()
    def op_xycb_8a(self): self.res_pxy_r()
    def op_xycb_8b(self): self.res_pxy_r()
    def op_xycb_8c(self): self.res_pxy_r()
    def op_xycb_8d(self): self.res_pxy_r()
    def op_xycb_8e(self): self.res_pxy()
    def op_xycb_8f(self): self.res_pxy_r()

    def op_xycb_90(self): self.res_pxy_r()
    def op_xycb_91(self): self.res_pxy_r()
    def op_xycb_92(self): self.res_pxy_r()
    def op_xycb_93(self): self.res_pxy_r()
    def op_xycb_94(self): self.res_pxy_r()
    def op_xycb_95(self): self.res_pxy_r()
    def op_xycb_96(self): self.res_pxy()
    def op_xycb_97(self): self.res_pxy_r()

    def op_xycb_98(self): self.res_pxy_r()
    def op_xycb_99(self): self.res_pxy_r()
    def op_xycb_9a(self): self.res_pxy_r()
    def op_xycb_9b(self): self.res_pxy_r()
    def op_xycb_9c(self): self.res_pxy_r()
    def op_xycb_9d(self): self.res_pxy_r()
    def op_xycb_9e(self): self.res_pxy()
    def op_xycb_9f(self): self.res_pxy_r()

    def op_xycb_a0(self): self.res_pxy_r()
    def op_xycb_a1(self): self.res_pxy_r()
    def op_xycb_a2(self): self.res_pxy_r()
    def op_xycb_a3(self): self.res_pxy_r()
    def op_xycb_a4(self): self.res_pxy_r()
    def op_xycb_a5(self): self.res_pxy_r()
    def op_xycb_a6(self): self.res_pxy()
    def op_xycb_a7(self): self.res_pxy_r()

    def op_xycb_a8(self): self.res_pxy_r()
    def op_xycb_a9(self): self.res_pxy_r()
    def op_xycb_aa(self): self.res_pxy_r()
    def op_xycb_ab(self): self.res_pxy_r()
    def op_xycb_ac(self): self.res_pxy_r()
    def op_xycb_ad(self): self.res_pxy_r()
    def op_xycb_ae(self): self.res_pxy()
    def op_xycb_af(self): self.res_pxy_r()

    def op_xycb_b0(self): self.res_pxy_r()
    def op_xycb_b1(self): self.res_pxy_r()
    def op_xycb_b2(self): self.res_pxy_r()
    def op_xycb_b3(self): self.res_pxy_r()
    def op_xycb_b4(self): self.res_pxy_r()
    def op_xycb_b5(self): self.res_pxy_r()
    def op_xycb_b6(self): self.res_pxy()
    def op_xycb_b7(self): self.res_pxy_r()

    def op_xycb_b8(self): self.res_pxy_r()
    def op_xycb_b9(self): self.res_pxy_r()
    def op_xycb_ba(self): self.res_pxy_r()
    def op_xycb_bb(self): self.res_pxy_r()
    def op_xycb_bc(self): self.res_pxy_r()
    def op_xycb_bd(self): self.res_pxy_r()
    def op_xycb_be(self): self.res_pxy()
    def op_xycb_bf(self): self.res_pxy_r()

    def op_xycb_c0(self): self.set_pxy_r()
    def op_xycb_c1(self): self.set_pxy_r()
    def op_xycb_c2(self): self.set_pxy_r()
    def op_xycb_c3(self): self.set_pxy_r()
    def op_xycb_c4(self): self.set_pxy_r()
    def op_xycb_c5(self): self.set_pxy_r()
    def op_xycb_c6(self): self.set_pxy()
    def op_xycb_c7(self): self.set_pxy_r()

    def op_xycb_c8(self): self.set_pxy_r()
    def op_xycb_c9(self): self.set_pxy_r()
    def op_xycb_ca(self): self.set_pxy_r()
    def op_xycb_cb(self): self.set_pxy_r()
    def op_xycb_cc(self): self.set_pxy_r()
    def op_xycb_cd(self): self.set_pxy_r()
    def op_xycb_ce(self): self.set_pxy()
    def op_xycb_cf(self): self.set_pxy_r()

    def op_xycb_d0(self): self.set_pxy_r()
    def op_xycb_d1(self): self.set_pxy_r()
    def op_xycb_d2(self): self.set_pxy_r()
    def op_xycb_d3(self): self.set_pxy_r()
    def op_xycb_d4(self): self.set_pxy_r()
    def op_xycb_d5(self): self.set_pxy_r()
    def op_xycb_d6(self): self.set_pxy()
    def op_xycb_d7(self): self.set_pxy_r()

    def op_xycb_d8(self): self.set_pxy_r()
    def op_xycb_d9(self): self.set_pxy_r()
    def op_xycb_da(self): self.set_pxy_r()
    def op_xycb_db(self): self.set_pxy_r()
    def op_xycb_dc(self): self.set_pxy_r()
    def op_xycb_dd(self): self.set_pxy_r()
    def op_xycb_de(self): self.set_pxy()
    def op_xycb_df(self): self.set_pxy_r()

    def op_xycb_e0(self): self.set_pxy_r()
    def op_xycb_e1(self): self.set_pxy_r()
    def op_xycb_e2(self): self.set_pxy_r()
    def op_xycb_e3(self): self.set_pxy_r()
    def op_xycb_e4(self): self.set_pxy_r()
    def op_xycb_e5(self): self.set_pxy_r()
    def op_xycb_e6(self): self.set_pxy()
    def op_xycb_e7(self): self.set_pxy_r()

    def op_xycb_e8(self): self.set_pxy_r()
    def op_xycb_e9(self): self.set_pxy_r()
    def op_xycb_ea(self): self.set_pxy_r()
    def op_xycb_eb(self): self.set_pxy_r()
    def op_xycb_ec(self): self.set_pxy_r()
    def op_xycb_ed(self): self.set_pxy_r()
    def op_xycb_ee(self): self.set_pxy()
    def op_xycb_ef(self): self.set_pxy_r()

    def op_xycb_f0(self): self.set_pxy_r()
    def op_xycb_f1(self): self.set_pxy_r()
    def op_xycb_f2(self): self.set_pxy_r()
    def op_xycb_f3(self): self.set_pxy_r()
    def op_xycb_f4(self): self.set_pxy_r()
    def op_xycb_f5(self): self.set_pxy_r()
    def op_xycb_f6(self): self.set_pxy()
    def op_xycb_f7(self): self.set_pxy_r()

    def op_xycb_f8(self): self.set_pxy_r()
    def op_xycb_f9(self): self.set_pxy_r()
    def op_xycb_fa(self): self.set_pxy_r()
    def op_xycb_fb(self): self.set_pxy_r()
    def op_xycb_fc(self): self.set_pxy_r()
    def op_xycb_fd(self): self.set_pxy_r()
    def op_xycb_fe(self): self.set_pxy()
    def op_xycb_ff(self): self.set_pxy_r()

    # IX register related opcodes (DD prefix)
    def op_dd_00(self): self.illegal(2)
    def op_dd_01(self): self.illegal(2)
    def op_dd_02(self): self.illegal(2)
    def op_dd_03(self): self.illegal(2)
    def op_dd_04(self): self.illegal(2)
    def op_dd_05(self): self.illegal(2)
    def op_dd_06(self): self.illegal(2)
    def op_dd_07(self): self.illegal(2)

    def op_dd_08(self): self.illegal(2)
    def op_dd_09(self): self.op_op_09()
    def op_dd_0a(self): self.illegal(2)
    def op_dd_0b(self): self.illegal(2)
    def op_dd_0c(self): self.illegal(2)
    def op_dd_0d(self): self.illegal(2)
    def op_dd_0e(self): self.illegal(2)
    def op_dd_0f(self): self.illegal(2)

    def op_dd_10(self): self.illegal(2)
    def op_dd_11(self): self.illegal(2)
    def op_dd_12(self): self.illegal(2)
    def op_dd_13(self): self.illegal(2)
    def op_dd_14(self): self.illegal(2)
    def op_dd_15(self): self.illegal(2)
    def op_dd_16(self): self.illegal(2)
    def op_dd_17(self): self.illegal(2)

    def op_dd_18(self): self.illegal(2)
    def op_dd_19(self): self.op_op_19()
    def op_dd_1a(self): self.illegal(2)
    def op_dd_1b(self): self.illegal(2)
    def op_dd_1c(self): self.illegal(2)
    def op_dd_1d(self): self.illegal(2)
    def op_dd_1e(self): self.illegal(2)
    def op_dd_1f(self): self.illegal(2)

    def op_dd_20(self): self.illegal(2)
    def op_dd_21(self): self.op_op_21()
    def op_dd_22(self): self.op_op_22()
    def op_dd_23(self): self.op_op_23()
    def op_dd_24(self): self.op_op_24()
    def op_dd_25(self): self.op_op_25()
    def op_dd_26(self): self.op_op_26()
    def op_dd_27(self): self.illegal(2)

    def op_dd_28(self): self.illegal(2)
    def op_dd_29(self): self.op_op_29()
    def op_dd_2a(self): self.op_op_2a()
    def op_dd_2b(self): self.op_op_2b()
    def op_dd_2c(self): self.op_op_2c()
    def op_dd_2d(self): self.op_op_2d()
    def op_dd_2e(self): self.op_op_2e()
    def op_dd_2f(self): self.illegal(2)

    def op_dd_30(self): self.illegal(2)
    def op_dd_31(self): self.illegal(2)
    def op_dd_32(self): self.illegal(2)
    def op_dd_33(self): self.illegal(2)
    def op_dd_34(self): self.inc_pxy()
    def op_dd_35(self): self.dec_pxy()
    def op_dd_36(self): self.ld_pxy_n()
    def op_dd_37(self): self.illegal(2)

    def op_dd_38(self): self.illegal(2)
    def op_dd_39(self): self.op_op_39()
    def op_dd_3a(self): self.illegal(2)
    def op_dd_3b(self): self.illegal(2)
    def op_dd_3c(self): self.illegal(2)
    def op_dd_3d(self): self.illegal(2)
    def op_dd_3e(self): self.illegal(2)
    def op_dd_3f(self): self.illegal(2)

    def op_dd_40(self): self.illegal(2)
    def op_dd_41(self): self.illegal(2)
    def op_dd_42(self): self.illegal(2)
    def op_dd_43(self): self.illegal(2)
    def op_dd_44(self): self.op_op_44()
    def op_dd_45(self): self.op_op_45()
    def op_dd_46(self): self.ld_r_pxy()
    def op_dd_47(self): self.illegal(2)

    def op_dd_48(self): self.illegal(2)
    def op_dd_49(self): self.illegal(2)
    def op_dd_4a(self): self.illegal(2)
    def op_dd_4b(self): self.illegal(2)
    def op_dd_4c(self): self.op_op_4c()
    def op_dd_4d(self): self.op_op_4d()
    def op_dd_4e(self): self.ld_r_pxy()
    def op_dd_4f(self): self.illegal(2)

    def op_dd_50(self): self.illegal(2)
    def op_dd_51(self): self.illegal(2)
    def op_dd_52(self): self.illegal(2)
    def op_dd_53(self): self.illegal(2)
    def op_dd_54(self): self.op_op_54()
    def op_dd_55(self): self.op_op_55()
    def op_dd_56(self): self.ld_r_pxy()
    def op_dd_57(self): self.illegal(2)

    def op_dd_58(self): self.illegal(2)
    def op_dd_59(self): self.illegal(2)
    def op_dd_5a(self): self.illegal(2)
    def op_dd_5b(self): self.illegal(2)
    def op_dd_5c(self): self.op_op_5c()
    def op_dd_5d(self): self.op_op_5d()
    def op_dd_5e(self): self.ld_r_pxy()
    def op_dd_5f(self): self.illegal(2)

    def op_dd_60(self): self.op_op_60()
    def op_dd_61(self): self.op_op_61()
    def op_dd_62(self): self.op_op_62()
    def op_dd_63(self): self.op_op_63()
    def op_dd_64(self): self.op_op_64()
    def op_dd_65(self): self.op_op_65()
    def op_dd_66(self): self.ld_r_pxy()
    def op_dd_67(self): self.op_op_67()

    def op_dd_68(self): self.op_op_68()
    def op_dd_69(self): self.op_op_69()
    def op_dd_6a(self): self.op_op_6a()
    def op_dd_6b(self): self.op_op_6b()
    def op_dd_6c(self): self.op_op_6c()
    def op_dd_6d(self): self.op_op_6d()
    def op_dd_6e(self): self.ld_r_pxy()
    def op_dd_6f(self): self.op_op_6f()

    def op_dd_70(self): self.ld_pxy_r()
    def op_dd_71(self): self.ld_pxy_r()
    def op_dd_72(self): self.ld_pxy_r()
    def op_dd_73(self): self.ld_pxy_r()
    def op_dd_74(self): self.ld_pxy_r()
    def op_dd_75(self): self.ld_pxy_r()
    def op_dd_76(self): self.illegal(2)
    def op_dd_77(self): self.ld_pxy_r()

    def op_dd_78(self): self.illegal(2)
    def op_dd_79(self): self.illegal(2)
    def op_dd_7a(self): self.illegal(2)
    def op_dd_7b(self): self.illegal(2)
    def op_dd_7c(self): self.op_op_7c()
    def op_dd_7d(self): self.op_op_7d()
    def op_dd_7e(self): self.ld_r_pxy()
    def op_dd_7f(self): self.illegal(2)

    def op_dd_80(self): self.illegal(2)
    def op_dd_81(self): self.illegal(2)
    def op_dd_82(self): self.illegal(2)
    def op_dd_83(self): self.illegal(2)
    def op_dd_84(self): self.op_op_84()
    def op_dd_85(self): self.op_op_85()
    def op_dd_86(self): self.add_a_pxy()
    def op_dd_87(self): self.illegal(2)

    def op_dd_88(self): self.illegal(2)
    def op_dd_89(self): self.illegal(2)
    def op_dd_8a(self): self.illegal(2)
    def op_dd_8b(self): self.illegal(2)
    def op_dd_8c(self): self.op_op_8c()
    def op_dd_8d(self): self.op_op_8d()
    def op_dd_8e(self): self.adc_a_pxy()
    def op_dd_8f(self): self.illegal(2)

    def op_dd_90(self): self.illegal(2)
    def op_dd_91(self): self.illegal(2)
    def op_dd_92(self): self.illegal(2)
    def op_dd_93(self): self.illegal(2)
    def op_dd_94(self): self.op_op_94()
    def op_dd_95(self): self.op_op_95()
    def op_dd_96(self): self.sub_pxy()
    def op_dd_97(self): self.illegal(2)

    def op_dd_98(self): self.illegal(2)
    def op_dd_99(self): self.illegal(2)
    def op_dd_9a(self): self.illegal(2)
    def op_dd_9b(self): self.illegal(2)
    def op_dd_9c(self): self.op_op_9c()
    def op_dd_9d(self): self.op_op_9d()
    def op_dd_9e(self): self.sbc_a_pxy()
    def op_dd_9f(self): self.illegal(2)

    def op_dd_a0(self): self.illegal(2)
    def op_dd_a1(self): self.illegal(2)
    def op_dd_a2(self): self.illegal(2)
    def op_dd_a3(self): self.illegal(2)
    def op_dd_a4(self): self.op_op_a4()
    def op_dd_a5(self): self.op_op_a5()
    def op_dd_a6(self): self.and_pxy()
    def op_dd_a7(self): self.illegal(2)

    def op_dd_a8(self): self.illegal(2)
    def op_dd_a9(self): self.illegal(2)
    def op_dd_aa(self): self.illegal(2)
    def op_dd_ab(self): self.illegal(2)
    def op_dd_ac(self): self.op_op_ac()
    def op_dd_ad(self): self.op_op_ad()
    def op_dd_ae(self): self.xor_pxy()
    def op_dd_af(self): self.illegal(2)

    def op_dd_b0(self): self.illegal(2)
    def op_dd_b1(self): self.illegal(2)
    def op_dd_b2(self): self.illegal(2)
    def op_dd_b3(self): self.illegal(2)
    def op_dd_b4(self): self.op_op_b4()
    def op_dd_b5(self): self.op_op_b5()
    def op_dd_b6(self): self.or_pxy()
    def op_dd_b7(self): self.illegal(2)

    def op_dd_b8(self): self.illegal(2)
    def op_dd_b9(self): self.illegal(2)
    def op_dd_ba(self): self.illegal(2)
    def op_dd_bb(self): self.illegal(2)
    def op_dd_bc(self): self.op_op_bc()
    def op_dd_bd(self): self.op_op_bd()
    def op_dd_be(self): self.cp_pxy()
    def op_dd_bf(self): self.illegal(2)

    def op_dd_c0(self): self.illegal(2)
    def op_dd_c1(self): self.illegal(2)
    def op_dd_c2(self): self.illegal(2)
    def op_dd_c3(self): self.illegal(2)
    def op_dd_c4(self): self.illegal(2)
    def op_dd_c5(self): self.illegal(2)
    def op_dd_c6(self): self.illegal(2)
    def op_dd_c7(self): self.illegal(2)

    def op_dd_c8(self): self.illegal(2)
    def op_dd_c9(self): self.illegal(2)
    def op_dd_ca(self): self.illegal(2)
    def op_dd_cb(self): self.ridx(); self.exec(self.op_xycb, self.rop())
    def op_dd_cc(self): self.illegal(2)
    def op_dd_cd(self): self.illegal(2)
    def op_dd_ce(self): self.illegal(2)
    def op_dd_cf(self): self.illegal(2)

    def op_dd_d0(self): self.illegal(2)
    def op_dd_d1(self): self.illegal(2)
    def op_dd_d2(self): self.illegal(2)
    def op_dd_d3(self): self.illegal(2)
    def op_dd_d4(self): self.illegal(2)
    def op_dd_d5(self): self.illegal(2)
    def op_dd_d6(self): self.illegal(2)
    def op_dd_d7(self): self.illegal(2)

    def op_dd_d8(self): self.illegal(2)
    def op_dd_d9(self): self.illegal(2)
    def op_dd_da(self): self.illegal(2)
    def op_dd_db(self): self.illegal(2)
    def op_dd_dc(self): self.illegal(2)
    def op_dd_dd(self): self.illegal(2)
    def op_dd_de(self): self.illegal(2)
    def op_dd_df(self): self.illegal(2)

    def op_dd_e0(self): self.illegal(2)
    def op_dd_e1(self): self.op_op_e1()
    def op_dd_e2(self): self.illegal(2)
    def op_dd_e3(self): self.op_op_e3()
    def op_dd_e4(self): self.illegal(2)
    def op_dd_e5(self): self.op_op_e5()
    def op_dd_e6(self): self.illegal(2)
    def op_dd_e7(self): self.illegal(2)

    def op_dd_e8(self): self.illegal(2)
    def op_dd_e9(self): self.op_op_e9()
    def op_dd_ea(self): self.illegal(2)
    def op_dd_eb(self): self.illegal(2)
    def op_dd_ec(self): self.illegal(2)
    def op_dd_ed(self): self.illegal(2)
    def op_dd_ee(self): self.illegal(2)
    def op_dd_ef(self): self.illegal(2)

    def op_dd_f0(self): self.illegal(2)
    def op_dd_f1(self): self.illegal(2)
    def op_dd_f2(self): self.illegal(2)
    def op_dd_f3(self): self.illegal(2)
    def op_dd_f4(self): self.illegal(2)
    def op_dd_f5(self): self.illegal(2)
    def op_dd_f6(self): self.illegal(2)
    def op_dd_f7(self): self.illegal(2)

    def op_dd_f8(self): self.illegal(2)
    def op_dd_f9(self): self.op_op_f9()
    def op_dd_fa(self): self.illegal(2)
    def op_dd_fb(self): self.illegal(2)
    def op_dd_fc(self): self.illegal(2)
    def op_dd_fd(self): self.illegal(2)
    def op_dd_fe(self): self.illegal(2)
    def op_dd_ff(self): self.illegal(2)

    # IY register related opcodes (FD prefix)
    # same as (DD prefix)

    # special opcodes (ED prefix)
    def op_ed_00(self): self.illegal(2)
    def op_ed_01(self): self.illegal(2)
    def op_ed_02(self): self.illegal(2)
    def op_ed_03(self): self.illegal(2)
    def op_ed_04(self): self.illegal(2)
    def op_ed_05(self): self.illegal(2)
    def op_ed_06(self): self.illegal(2)
    def op_ed_07(self): self.illegal(2)

    def op_ed_08(self): self.illegal(2)
    def op_ed_09(self): self.illegal(2)
    def op_ed_0a(self): self.illegal(2)
    def op_ed_0b(self): self.illegal(2)
    def op_ed_0c(self): self.illegal(2)
    def op_ed_0d(self): self.illegal(2)
    def op_ed_0e(self): self.illegal(2)
    def op_ed_0f(self): self.illegal(2)

    def op_ed_10(self): self.illegal(2)
    def op_ed_11(self): self.illegal(2)
    def op_ed_12(self): self.illegal(2)
    def op_ed_13(self): self.illegal(2)
    def op_ed_14(self): self.illegal(2)
    def op_ed_15(self): self.illegal(2)
    def op_ed_16(self): self.illegal(2)
    def op_ed_17(self): self.illegal(2)

    def op_ed_18(self): self.illegal(2)
    def op_ed_19(self): self.illegal(2)
    def op_ed_1a(self): self.illegal(2)
    def op_ed_1b(self): self.illegal(2)
    def op_ed_1c(self): self.illegal(2)
    def op_ed_1d(self): self.illegal(2)
    def op_ed_1e(self): self.illegal(2)
    def op_ed_1f(self): self.illegal(2)

    def op_ed_20(self): self.illegal(2)
    def op_ed_21(self): self.illegal(2)
    def op_ed_22(self): self.illegal(2)
    def op_ed_23(self): self.illegal(2)
    def op_ed_24(self): self.illegal(2)
    def op_ed_25(self): self.illegal(2)
    def op_ed_26(self): self.illegal(2)
    def op_ed_27(self): self.illegal(2)

    def op_ed_28(self): self.illegal(2)
    def op_ed_29(self): self.illegal(2)
    def op_ed_2a(self): self.illegal(2)
    def op_ed_2b(self): self.illegal(2)
    def op_ed_2c(self): self.illegal(2)
    def op_ed_2d(self): self.illegal(2)
    def op_ed_2e(self): self.illegal(2)
    def op_ed_2f(self): self.illegal(2)

    def op_ed_30(self): self.illegal(2)
    def op_ed_31(self): self.illegal(2)
    def op_ed_32(self): self.illegal(2)
    def op_ed_33(self): self.illegal(2)
    def op_ed_34(self): self.illegal(2)
    def op_ed_35(self): self.illegal(2)
    def op_ed_36(self): self.illegal(2)
    def op_ed_37(self): self.illegal(2)

    def op_ed_38(self): self.illegal(2)
    def op_ed_39(self): self.illegal(2)
    def op_ed_3a(self): self.illegal(2)
    def op_ed_3b(self): self.illegal(2)
    def op_ed_3c(self): self.illegal(2)
    def op_ed_3d(self): self.illegal(2)
    def op_ed_3e(self): self.illegal(2)
    def op_ed_3f(self): self.illegal(2)

    def op_ed_40(self): self.in_r_pc()
    def op_ed_41(self): self.out_pc_r()
    def op_ed_42(self): self.sbc_hl_ss()
    def op_ed_43(self): self.ld_pnn_dd()
    def op_ed_44(self): self.neg()
    def op_ed_45(self): self.retn()
    def op_ed_46(self): self.im_0()
    def op_ed_47(self): self.ld_i_a()

    def op_ed_48(self): self.in_r_pc()
    def op_ed_49(self): self.out_pc_r()
    def op_ed_4a(self): self.adc_hl_ss()
    def op_ed_4b(self): self.ld_dd_pnn()
    def op_ed_4c(self): self.neg()
    def op_ed_4d(self): self.reti()
    def op_ed_4e(self): self.im_0()
    def op_ed_4f(self): self.ld_r_a()

    def op_ed_50(self): self.in_r_pc()
    def op_ed_51(self): self.out_pc_r()
    def op_ed_52(self): self.sbc_hl_ss()
    def op_ed_53(self): self.ld_pnn_dd()
    def op_ed_54(self): self.neg()
    def op_ed_55(self): self.retn()
    def op_ed_56(self): self.im_1()
    def op_ed_57(self): self.ld_a_i()

    def op_ed_58(self): self.in_r_pc()
    def op_ed_59(self): self.out_pc_r()
    def op_ed_5a(self): self.adc_hl_ss()
    def op_ed_5b(self): self.ld_dd_pnn()
    def op_ed_5c(self): self.neg()
    def op_ed_5d(self): self.retn()
    def op_ed_5e(self): self.im_2()
    def op_ed_5f(self): self.ld_a_r()

    def op_ed_60(self): self.in_r_pc()
    def op_ed_61(self): self.out_pc_r()
    def op_ed_62(self): self.sbc_hl_ss()
    def op_ed_63(self): self.ld_pnn_dd()
    def op_ed_64(self): self.neg()
    def op_ed_65(self): self.retn()
    def op_ed_66(self): self.im_0()
    def op_ed_67(self): self.rrd()

    def op_ed_68(self): self.in_r_pc()
    def op_ed_69(self): self.out_pc_r()
    def op_ed_6a(self): self.adc_hl_ss()
    def op_ed_6b(self): self.ld_dd_pnn()
    def op_ed_6c(self): self.neg()
    def op_ed_6d(self): self.retn()
    def op_ed_6e(self): self.im_0()
    def op_ed_6f(self): self.rld()

    def op_ed_70(self): self.in_f_pc()
    def op_ed_71(self): self.out_pc_0()
    def op_ed_72(self): self.sbc_hl_ss()
    def op_ed_73(self): self.ld_pnn_dd()
    def op_ed_74(self): self.neg()
    def op_ed_75(self): self.retn()
    def op_ed_76(self): self.im_1()
    def op_ed_77(self): self.illegal(2)

    def op_ed_78(self): self.in_r_pc()
    def op_ed_79(self): self.out_pc_r()
    def op_ed_7a(self): self.adc_hl_ss()
    def op_ed_7b(self): self.ld_dd_pnn()
    def op_ed_7c(self): self.neg()
    def op_ed_7d(self): self.retn()
    def op_ed_7e(self): self.im_2()
    def op_ed_7f(self): self.illegal(2)

    def op_ed_80(self): self.illegal(2)
    def op_ed_81(self): self.illegal(2)
    def op_ed_82(self): self.illegal(2)
    def op_ed_83(self): self.illegal(2)
    def op_ed_84(self): self.illegal(2)
    def op_ed_85(self): self.illegal(2)
    def op_ed_86(self): self.illegal(2)
    def op_ed_87(self): self.illegal(2)

    def op_ed_88(self): self.illegal(2)
    def op_ed_89(self): self.illegal(2)
    def op_ed_8a(self): self.illegal(2)
    def op_ed_8b(self): self.illegal(2)
    def op_ed_8c(self): self.illegal(2)
    def op_ed_8d(self): self.illegal(2)
    def op_ed_8e(self): self.illegal(2)
    def op_ed_8f(self): self.illegal(2)

    def op_ed_90(self): self.illegal(2)
    def op_ed_91(self): self.illegal(2)
    def op_ed_92(self): self.illegal(2)
    def op_ed_93(self): self.illegal(2)
    def op_ed_94(self): self.illegal(2)
    def op_ed_95(self): self.illegal(2)
    def op_ed_96(self): self.illegal(2)
    def op_ed_97(self): self.illegal(2)

    def op_ed_98(self): self.illegal(2)
    def op_ed_99(self): self.illegal(2)
    def op_ed_9a(self): self.illegal(2)
    def op_ed_9b(self): self.illegal(2)
    def op_ed_9c(self): self.illegal(2)
    def op_ed_9d(self): self.illegal(2)
    def op_ed_9e(self): self.illegal(2)
    def op_ed_9f(self): self.illegal(2)

    def op_ed_a0(self): self.ldi()
    def op_ed_a1(self): self.cpi()
    def op_ed_a2(self): self.ini()
    def op_ed_a3(self): self.outi()
    def op_ed_a4(self): self.illegal(2)
    def op_ed_a5(self): self.illegal(2)
    def op_ed_a6(self): self.illegal(2)
    def op_ed_a7(self): self.illegal(2)

    def op_ed_a8(self): self.ldd()
    def op_ed_a9(self): self.cpd()
    def op_ed_aa(self): self.ind()
    def op_ed_ab(self): self.outd()
    def op_ed_ac(self): self.illegal(2)
    def op_ed_ad(self): self.illegal(2)
    def op_ed_ae(self): self.illegal(2)
    def op_ed_af(self): self.illegal(2)

    def op_ed_b0(self): self.ldir()
    def op_ed_b1(self): self.cpir()
    def op_ed_b2(self): self.inir()
    def op_ed_b3(self): self.otir()
    def op_ed_b4(self): self.illegal(2)
    def op_ed_b5(self): self.illegal(2)
    def op_ed_b6(self): self.illegal(2)
    def op_ed_b7(self): self.illegal(2)

    def op_ed_b8(self): self.lddr()
    def op_ed_b9(self): self.cpdr()
    def op_ed_ba(self): self.indr()
    def op_ed_bb(self): self.otdr()
    def op_ed_bc(self): self.illegal(2)
    def op_ed_bd(self): self.illegal(2)
    def op_ed_be(self): self.illegal(2)
    def op_ed_bf(self): self.illegal(2)

    def op_ed_c0(self): self.illegal(2)
    def op_ed_c1(self): self.illegal(2)
    def op_ed_c2(self): self.illegal(2)
    def op_ed_c3(self): self.illegal(2)
    def op_ed_c4(self): self.illegal(2)
    def op_ed_c5(self): self.illegal(2)
    def op_ed_c6(self): self.illegal(2)
    def op_ed_c7(self): self.illegal(2)

    def op_ed_c8(self): self.illegal(2)
    def op_ed_c9(self): self.illegal(2)
    def op_ed_ca(self): self.illegal(2)
    def op_ed_cb(self): self.illegal(2)
    def op_ed_cc(self): self.illegal(2)
    def op_ed_cd(self): self.illegal(2)
    def op_ed_ce(self): self.illegal(2)
    def op_ed_cf(self): self.illegal(2)

    def op_ed_d0(self): self.illegal(2)
    def op_ed_d1(self): self.illegal(2)
    def op_ed_d2(self): self.illegal(2)
    def op_ed_d3(self): self.illegal(2)
    def op_ed_d4(self): self.illegal(2)
    def op_ed_d5(self): self.illegal(2)
    def op_ed_d6(self): self.illegal(2)
    def op_ed_d7(self): self.illegal(2)

    def op_ed_d8(self): self.illegal(2)
    def op_ed_d9(self): self.illegal(2)
    def op_ed_da(self): self.illegal(2)
    def op_ed_db(self): self.illegal(2)
    def op_ed_dc(self): self.illegal(2)
    def op_ed_dd(self): self.illegal(2)
    def op_ed_de(self): self.illegal(2)
    def op_ed_df(self): self.illegal(2)

    def op_ed_e0(self): self.illegal(2)
    def op_ed_e1(self): self.illegal(2)
    def op_ed_e2(self): self.illegal(2)
    def op_ed_e3(self): self.illegal(2)
    def op_ed_e4(self): self.illegal(2)
    def op_ed_e5(self): self.illegal(2)
    def op_ed_e6(self): self.illegal(2)
    def op_ed_e7(self): self.illegal(2)

    def op_ed_e8(self): self.illegal(2)
    def op_ed_e9(self): self.illegal(2)
    def op_ed_ea(self): self.illegal(2)
    def op_ed_eb(self): self.illegal(2)
    def op_ed_ec(self): self.illegal(2)
    def op_ed_ed(self): self.illegal(2)
    def op_ed_ee(self): self.illegal(2)
    def op_ed_ef(self): self.illegal(2)

    def op_ed_f0(self): self.illegal(2)
    def op_ed_f1(self): self.illegal(2)
    def op_ed_f2(self): self.illegal(2)
    def op_ed_f3(self): self.illegal(2)
    def op_ed_f4(self): self.illegal(2)
    def op_ed_f5(self): self.illegal(2)
    def op_ed_f6(self): self.illegal(2)
    def op_ed_f7(self): self.illegal(2)

    def op_ed_f8(self): self.illegal(2)
    def op_ed_f9(self): self.illegal(2)
    def op_ed_fa(self): self.illegal(2)
    def op_ed_fb(self): self.illegal(2)
    def op_ed_fc(self): self.illegal(2)
    def op_ed_fd(self): self.illegal(2)
    def op_ed_fe(self): self.illegal(2)
    def op_ed_ff(self): self.illegal(2)

    # main opcodes
    def op_op_00(self): self.nop()
    def op_op_01(self): self.ld_dd_nn()
    def op_op_02(self): self.ld_pbc_a()
    def op_op_03(self): self.inc_ss()
    def op_op_04(self): self.inc_r()
    def op_op_05(self): self.dec_r()
    def op_op_06(self): self.ld_r_n()
    def op_op_07(self): self.rlca()
    def op_op_08(self): self.ex_af_af()
    def op_op_09(self): self.add_hl_ss()
    def op_op_0a(self): self.ld_a_pbc()
    def op_op_0b(self): self.dec_ss()
    def op_op_0c(self): self.inc_r()
    def op_op_0d(self): self.dec_r()
    def op_op_0e(self): self.ld_r_n()
    def op_op_0f(self): self.rrca()

    def op_op_10(self): self.djnz_e()
    def op_op_11(self): self.ld_dd_nn()
    def op_op_12(self): self.ld_pde_a()
    def op_op_13(self): self.inc_ss()
    def op_op_14(self): self.inc_r()
    def op_op_15(self): self.dec_r()
    def op_op_16(self): self.ld_r_n()
    def op_op_17(self): self.rla()
    def op_op_18(self): self.jr_e()
    def op_op_19(self): self.add_hl_ss()
    def op_op_1a(self): self.ld_a_pde()
    def op_op_1b(self): self.dec_ss()
    def op_op_1c(self): self.inc_r()
    def op_op_1d(self): self.dec_r()
    def op_op_1e(self): self.ld_r_n()
    def op_op_1f(self): self.rra()

    def op_op_20(self): self.jr_ss_e()
    def op_op_21(self): self.ld_dd_nn()
    def op_op_22(self): self.ld_pnn_hl()
    def op_op_23(self): self.inc_ss()
    def op_op_24(self): self.inc_r()
    def op_op_25(self): self.dec_r()
    def op_op_26(self): self.ld_r_n()
    def op_op_27(self): self.daa()
    def op_op_28(self): self.jr_ss_e()
    def op_op_29(self): self.add_hl_ss()
    def op_op_2a(self): self.ld_hl_pnn()
    def op_op_2b(self): self.dec_ss()
    def op_op_2c(self): self.inc_r()
    def op_op_2d(self): self.dec_r()
    def op_op_2e(self): self.ld_r_n()
    def op_op_2f(self): self.cpl()

    def op_op_30(self): self.jr_ss_e()
    def op_op_31(self): self.ld_dd_nn()
    def op_op_32(self): self.ld_pnn_a()
    def op_op_33(self): self.inc_ss()
    def op_op_34(self): self.inc_r()
    def op_op_35(self): self.dec_r()
    def op_op_36(self): self.ld_r_n()
    def op_op_37(self): self.scf()
    def op_op_38(self): self.jr_ss_e()
    def op_op_39(self): self.add_hl_ss()
    def op_op_3a(self): self.ld_a_pnn()
    def op_op_3b(self): self.dec_ss()
    def op_op_3c(self): self.inc_r()
    def op_op_3d(self): self.dec_r()
    def op_op_3e(self): self.ld_r_n()
    def op_op_3f(self): self.ccf()

    def op_op_40(self): self.ld_r_r()
    def op_op_41(self): self.ld_r_r()
    def op_op_42(self): self.ld_r_r()
    def op_op_43(self): self.ld_r_r()
    def op_op_44(self): self.ld_r_r()
    def op_op_45(self): self.ld_r_r()
    def op_op_46(self): self.ld_r_r()
    def op_op_47(self): self.ld_r_r()
    def op_op_48(self): self.ld_r_r()
    def op_op_49(self): self.ld_r_r()
    def op_op_4a(self): self.ld_r_r()
    def op_op_4b(self): self.ld_r_r()
    def op_op_4c(self): self.ld_r_r()
    def op_op_4d(self): self.ld_r_r()
    def op_op_4e(self): self.ld_r_r()
    def op_op_4f(self): self.ld_r_r()

    def op_op_50(self): self.ld_r_r()
    def op_op_51(self): self.ld_r_r()
    def op_op_52(self): self.ld_r_r()
    def op_op_53(self): self.ld_r_r()
    def op_op_54(self): self.ld_r_r()
    def op_op_55(self): self.ld_r_r()
    def op_op_56(self): self.ld_r_r()
    def op_op_57(self): self.ld_r_r()
    def op_op_58(self): self.ld_r_r()
    def op_op_59(self): self.ld_r_r()
    def op_op_5a(self): self.ld_r_r()
    def op_op_5b(self): self.ld_r_r()
    def op_op_5c(self): self.ld_r_r()
    def op_op_5d(self): self.ld_r_r()
    def op_op_5e(self): self.ld_r_r()
    def op_op_5f(self): self.ld_r_r()

    def op_op_60(self): self.ld_r_r()
    def op_op_61(self): self.ld_r_r()
    def op_op_62(self): self.ld_r_r()
    def op_op_63(self): self.ld_r_r()
    def op_op_64(self): self.ld_r_r()
    def op_op_65(self): self.ld_r_r()
    def op_op_66(self): self.ld_r_r()
    def op_op_67(self): self.ld_r_r()
    def op_op_68(self): self.ld_r_r()
    def op_op_69(self): self.ld_r_r()
    def op_op_6a(self): self.ld_r_r()
    def op_op_6b(self): self.ld_r_r()
    def op_op_6c(self): self.ld_r_r()
    def op_op_6d(self): self.ld_r_r()
    def op_op_6e(self): self.ld_r_r()
    def op_op_6f(self): self.ld_r_r()

    def op_op_70(self): self.ld_r_r()
    def op_op_71(self): self.ld_r_r()
    def op_op_72(self): self.ld_r_r()
    def op_op_73(self): self.ld_r_r()
    def op_op_74(self): self.ld_r_r()
    def op_op_75(self): self.ld_r_r()
    def op_op_76(self): self.halt()
    def op_op_77(self): self.ld_r_r()
    def op_op_78(self): self.ld_r_r()
    def op_op_79(self): self.ld_r_r()
    def op_op_7a(self): self.ld_r_r()
    def op_op_7b(self): self.ld_r_r()
    def op_op_7c(self): self.ld_r_r()
    def op_op_7d(self): self.ld_r_r()
    def op_op_7e(self): self.ld_r_r()
    def op_op_7f(self): self.ld_r_r()

    def op_op_80(self): self.add_a_r()
    def op_op_81(self): self.add_a_r()
    def op_op_82(self): self.add_a_r()
    def op_op_83(self): self.add_a_r()
    def op_op_84(self): self.add_a_r()
    def op_op_85(self): self.add_a_r()
    def op_op_86(self): self.add_a_r()
    def op_op_87(self): self.add_a_r()
    def op_op_88(self): self.adc_a_r()
    def op_op_89(self): self.adc_a_r()
    def op_op_8a(self): self.adc_a_r()
    def op_op_8b(self): self.adc_a_r()
    def op_op_8c(self): self.adc_a_r()
    def op_op_8d(self): self.adc_a_r()
    def op_op_8e(self): self.adc_a_r()
    def op_op_8f(self): self.adc_a_r()

    def op_op_90(self): self.sub_r()
    def op_op_91(self): self.sub_r()
    def op_op_92(self): self.sub_r()
    def op_op_93(self): self.sub_r()
    def op_op_94(self): self.sub_r()
    def op_op_95(self): self.sub_r()
    def op_op_96(self): self.sub_r()
    def op_op_97(self): self.sub_r()
    def op_op_98(self): self.sbc_a_r()
    def op_op_99(self): self.sbc_a_r()
    def op_op_9a(self): self.sbc_a_r()
    def op_op_9b(self): self.sbc_a_r()
    def op_op_9c(self): self.sbc_a_r()
    def op_op_9d(self): self.sbc_a_r()
    def op_op_9e(self): self.sbc_a_r()
    def op_op_9f(self): self.sbc_a_r()

    def op_op_a0(self): self.and_r()
    def op_op_a1(self): self.and_r()
    def op_op_a2(self): self.and_r()
    def op_op_a3(self): self.and_r()
    def op_op_a4(self): self.and_r()
    def op_op_a5(self): self.and_r()
    def op_op_a6(self): self.and_r()
    def op_op_a7(self): self.and_r()
    def op_op_a8(self): self.xor_r()
    def op_op_a9(self): self.xor_r()
    def op_op_aa(self): self.xor_r()
    def op_op_ab(self): self.xor_r()
    def op_op_ac(self): self.xor_r()
    def op_op_ad(self): self.xor_r()
    def op_op_ae(self): self.xor_r()
    def op_op_af(self): self.xor_r()

    def op_op_b0(self): self.or_r()
    def op_op_b1(self): self.or_r()
    def op_op_b2(self): self.or_r()
    def op_op_b3(self): self.or_r()
    def op_op_b4(self): self.or_r()
    def op_op_b5(self): self.or_r()
    def op_op_b6(self): self.or_r()
    def op_op_b7(self): self.or_r()
    def op_op_b8(self): self.cp_r()
    def op_op_b9(self): self.cp_r()
    def op_op_ba(self): self.cp_r()
    def op_op_bb(self): self.cp_r()
    def op_op_bc(self): self.cp_r()
    def op_op_bd(self): self.cp_r()
    def op_op_be(self): self.cp_r()
    def op_op_bf(self): self.cp_r()

    def op_op_c0(self): self.ret_cc()
    def op_op_c1(self): self.pop_qq()
    def op_op_c2(self): self.jp_cc_nn()
    def op_op_c3(self): self.jp_nn()
    def op_op_c4(self): self.call_cc_nn()
    def op_op_c5(self): self.push_qq()
    def op_op_c6(self): self.add_a_n()
    def op_op_c7(self): self.rst_p()
    def op_op_c8(self): self.ret_cc()
    def op_op_c9(self): self.ret()
    def op_op_ca(self): self.jp_cc_nn()
    def op_op_cb(self): self.exec(self.op_cb, self.rop())
    def op_op_cc(self): self.call_cc_nn()
    def op_op_cd(self): self.call_nn()
    def op_op_ce(self): self.adc_a_n()
    def op_op_cf(self): self.rst_p()

    def op_op_d0(self): self.ret_cc()
    def op_op_d1(self): self.pop_qq()
    def op_op_d2(self): self.jp_cc_nn()
    def op_op_d3(self): self.out_pn_a()
    def op_op_d4(self): self.call_cc_nn()
    def op_op_d5(self): self.push_qq()
    def op_op_d6(self): self.sub_n()
    def op_op_d7(self): self.rst_p()
    def op_op_d8(self): self.ret_cc()
    def op_op_d9(self): self.exx()
    def op_op_da(self): self.jp_cc_nn()
    def op_op_db(self): self.in_a_pn()
    def op_op_dc(self): self.call_cc_nn()
    def op_op_dd(self): self.reg_ix(); self.exec(self.op_dd, self.rop())
    def op_op_de(self): self.sbc_a_n()
    def op_op_df(self): self.rst_p()

    def op_op_e0(self): self.ret_cc()
    def op_op_e1(self): self.pop_qq()
    def op_op_e2(self): self.jp_cc_nn()
    def op_op_e3(self): self.ex_psp_hl()
    def op_op_e4(self): self.call_cc_nn()
    def op_op_e5(self): self.push_qq()
    def op_op_e6(self): self.and_n()
    def op_op_e7(self): self.rst_p()
    def op_op_e8(self): self.ret_cc()
    def op_op_e9(self): self.jp_phl()
    def op_op_ea(self): self.jp_cc_nn()
    def op_op_eb(self): self.ex_de_hl()
    def op_op_ec(self): self.call_cc_nn()
    def op_op_ed(self): self.exec(self.op_ed, self.rop())
    def op_op_ee(self): self.xor_n()
    def op_op_ef(self): self.rst_p()

    def op_op_f0(self): self.ret_cc()
    def op_op_f1(self): self.pop_qq()
    def op_op_f2(self): self.jp_cc_nn()
    def op_op_f3(self): self.di()
    def op_op_f4(self): self.call_cc_nn()
    def op_op_f5(self): self.push_qq()
    def op_op_f6(self): self.or_n()
    def op_op_f7(self): self.rst_p()
    def op_op_f8(self): self.ret_cc()
    def op_op_f9(self): self.ld_sp_hl()
    def op_op_fa(self): self.jp_cc_nn()
    def op_op_fb(self): self.ei()
    def op_op_fc(self): self.call_cc_nn()
    def op_op_fd(self): self.reg_iy(); self.exec(self.op_fd, self.rop())
    def op_op_fe(self): self.cp_n()
    def op_op_ff(self): self.rst_p()

    def initialize_mnemonics(self):
        self.m_reg8n = ["b", "c", "d", "e", "h", "l", "(hl)", "a"]
        self.m_reg16n = ["bc", "de", "hl", "sp"]
        self.m_reg16an = ["bc", "de", "hl", "af"]

        self.m_reg8x = ["b", "c", "d", "e", "ixh", "ixl", "(hl)", "a"]
        self.m_reg16x = ["bc", "de", "ix", "sp"]
        self.m_reg16ax = ["bc", "de", "ix", "af"]

        self.m_reg8y = ["b", "c", "d", "e", "iyh", "iyl", "(hl)", "a"]
        self.m_reg16y = ["bc", "de", "iy", "sp"]
        self.m_reg16ay = ["bc", "de", "iy", "af"]

        self.reg_n()

        self.m_cc = ["nz", "z", "nc", "c", "po", "pe", "p", "m"]

    def initialize_tables(self):
        self.s8 = [0] * 0x100
        for i in range(0x100):
            value = -(i & 0b10000000) | (i & 0b01111111)
            self.s8[i] = value

        self.op_cb = [
            self.op_cb_00, self.op_cb_01, self.op_cb_02, self.op_cb_03,
            self.op_cb_04, self.op_cb_05, self.op_cb_06, self.op_cb_07,
            self.op_cb_08, self.op_cb_09, self.op_cb_0a, self.op_cb_0b,
            self.op_cb_0c, self.op_cb_0d, self.op_cb_0e, self.op_cb_0f,
            self.op_cb_10, self.op_cb_11, self.op_cb_12, self.op_cb_13,
            self.op_cb_14, self.op_cb_15, self.op_cb_16, self.op_cb_17,
            self.op_cb_18, self.op_cb_19, self.op_cb_1a, self.op_cb_1b,
            self.op_cb_1c, self.op_cb_1d, self.op_cb_1e, self.op_cb_1f,
            self.op_cb_20, self.op_cb_21, self.op_cb_22, self.op_cb_23,
            self.op_cb_24, self.op_cb_25, self.op_cb_26, self.op_cb_27,
            self.op_cb_28, self.op_cb_29, self.op_cb_2a, self.op_cb_2b,
            self.op_cb_2c, self.op_cb_2d, self.op_cb_2e, self.op_cb_2f,
            self.op_cb_30, self.op_cb_31, self.op_cb_32, self.op_cb_33,
            self.op_cb_34, self.op_cb_35, self.op_cb_36, self.op_cb_37,
            self.op_cb_38, self.op_cb_39, self.op_cb_3a, self.op_cb_3b,
            self.op_cb_3c, self.op_cb_3d, self.op_cb_3e, self.op_cb_3f,
            self.op_cb_40, self.op_cb_41, self.op_cb_42, self.op_cb_43,
            self.op_cb_44, self.op_cb_45, self.op_cb_46, self.op_cb_47,
            self.op_cb_48, self.op_cb_49, self.op_cb_4a, self.op_cb_4b,
            self.op_cb_4c, self.op_cb_4d, self.op_cb_4e, self.op_cb_4f,
            self.op_cb_50, self.op_cb_51, self.op_cb_52, self.op_cb_53,
            self.op_cb_54, self.op_cb_55, self.op_cb_56, self.op_cb_57,
            self.op_cb_58, self.op_cb_59, self.op_cb_5a, self.op_cb_5b,
            self.op_cb_5c, self.op_cb_5d, self.op_cb_5e, self.op_cb_5f,
            self.op_cb_60, self.op_cb_61, self.op_cb_62, self.op_cb_63,
            self.op_cb_64, self.op_cb_65, self.op_cb_66, self.op_cb_67,
            self.op_cb_68, self.op_cb_69, self.op_cb_6a, self.op_cb_6b,
            self.op_cb_6c, self.op_cb_6d, self.op_cb_6e, self.op_cb_6f,
            self.op_cb_70, self.op_cb_71, self.op_cb_72, self.op_cb_73,
            self.op_cb_74, self.op_cb_75, self.op_cb_76, self.op_cb_77,
            self.op_cb_78, self.op_cb_79, self.op_cb_7a, self.op_cb_7b,
            self.op_cb_7c, self.op_cb_7d, self.op_cb_7e, self.op_cb_7f,
            self.op_cb_80, self.op_cb_81, self.op_cb_82, self.op_cb_83,
            self.op_cb_84, self.op_cb_85, self.op_cb_86, self.op_cb_87,
            self.op_cb_88, self.op_cb_89, self.op_cb_8a, self.op_cb_8b,
            self.op_cb_8c, self.op_cb_8d, self.op_cb_8e, self.op_cb_8f,
            self.op_cb_90, self.op_cb_91, self.op_cb_92, self.op_cb_93,
            self.op_cb_94, self.op_cb_95, self.op_cb_96, self.op_cb_97,
            self.op_cb_98, self.op_cb_99, self.op_cb_9a, self.op_cb_9b,
            self.op_cb_9c, self.op_cb_9d, self.op_cb_9e, self.op_cb_9f,
            self.op_cb_a0, self.op_cb_a1, self.op_cb_a2, self.op_cb_a3,
            self.op_cb_a4, self.op_cb_a5, self.op_cb_a6, self.op_cb_a7,
            self.op_cb_a8, self.op_cb_a9, self.op_cb_aa, self.op_cb_ab,
            self.op_cb_ac, self.op_cb_ad, self.op_cb_ae, self.op_cb_af,
            self.op_cb_b0, self.op_cb_b1, self.op_cb_b2, self.op_cb_b3,
            self.op_cb_b4, self.op_cb_b5, self.op_cb_b6, self.op_cb_b7,
            self.op_cb_b8, self.op_cb_b9, self.op_cb_ba, self.op_cb_bb,
            self.op_cb_bc, self.op_cb_bd, self.op_cb_be, self.op_cb_bf,
            self.op_cb_c0, self.op_cb_c1, self.op_cb_c2, self.op_cb_c3,
            self.op_cb_c4, self.op_cb_c5, self.op_cb_c6, self.op_cb_c7,
            self.op_cb_c8, self.op_cb_c9, self.op_cb_ca, self.op_cb_cb,
            self.op_cb_cc, self.op_cb_cd, self.op_cb_ce, self.op_cb_cf,
            self.op_cb_d0, self.op_cb_d1, self.op_cb_d2, self.op_cb_d3,
            self.op_cb_d4, self.op_cb_d5, self.op_cb_d6, self.op_cb_d7,
            self.op_cb_d8, self.op_cb_d9, self.op_cb_da, self.op_cb_db,
            self.op_cb_dc, self.op_cb_dd, self.op_cb_de, self.op_cb_df,
            self.op_cb_e0, self.op_cb_e1, self.op_cb_e2, self.op_cb_e3,
            self.op_cb_e4, self.op_cb_e5, self.op_cb_e6, self.op_cb_e7,
            self.op_cb_e8, self.op_cb_e9, self.op_cb_ea, self.op_cb_eb,
            self.op_cb_ec, self.op_cb_ed, self.op_cb_ee, self.op_cb_ef,
            self.op_cb_f0, self.op_cb_f1, self.op_cb_f2, self.op_cb_f3,
            self.op_cb_f4, self.op_cb_f5, self.op_cb_f6, self.op_cb_f7,
            self.op_cb_f8, self.op_cb_f9, self.op_cb_fa, self.op_cb_fb,
            self.op_cb_fc, self.op_cb_fd, self.op_cb_fe, self.op_cb_ff,
        ]
        self.op_xycb = [
            self.op_xycb_00, self.op_xycb_01, self.op_xycb_02, self.op_xycb_03,
            self.op_xycb_04, self.op_xycb_05, self.op_xycb_06, self.op_xycb_07,
            self.op_xycb_08, self.op_xycb_09, self.op_xycb_0a, self.op_xycb_0b,
            self.op_xycb_0c, self.op_xycb_0d, self.op_xycb_0e, self.op_xycb_0f,
            self.op_xycb_10, self.op_xycb_11, self.op_xycb_12, self.op_xycb_13,
            self.op_xycb_14, self.op_xycb_15, self.op_xycb_16, self.op_xycb_17,
            self.op_xycb_18, self.op_xycb_19, self.op_xycb_1a, self.op_xycb_1b,
            self.op_xycb_1c, self.op_xycb_1d, self.op_xycb_1e, self.op_xycb_1f,
            self.op_xycb_20, self.op_xycb_21, self.op_xycb_22, self.op_xycb_23,
            self.op_xycb_24, self.op_xycb_25, self.op_xycb_26, self.op_xycb_27,
            self.op_xycb_28, self.op_xycb_29, self.op_xycb_2a, self.op_xycb_2b,
            self.op_xycb_2c, self.op_xycb_2d, self.op_xycb_2e, self.op_xycb_2f,
            self.op_xycb_30, self.op_xycb_31, self.op_xycb_32, self.op_xycb_33,
            self.op_xycb_34, self.op_xycb_35, self.op_xycb_36, self.op_xycb_37,
            self.op_xycb_38, self.op_xycb_39, self.op_xycb_3a, self.op_xycb_3b,
            self.op_xycb_3c, self.op_xycb_3d, self.op_xycb_3e, self.op_xycb_3f,
            self.op_xycb_40, self.op_xycb_41, self.op_xycb_42, self.op_xycb_43,
            self.op_xycb_44, self.op_xycb_45, self.op_xycb_46, self.op_xycb_47,
            self.op_xycb_48, self.op_xycb_49, self.op_xycb_4a, self.op_xycb_4b,
            self.op_xycb_4c, self.op_xycb_4d, self.op_xycb_4e, self.op_xycb_4f,
            self.op_xycb_50, self.op_xycb_51, self.op_xycb_52, self.op_xycb_53,
            self.op_xycb_54, self.op_xycb_55, self.op_xycb_56, self.op_xycb_57,
            self.op_xycb_58, self.op_xycb_59, self.op_xycb_5a, self.op_xycb_5b,
            self.op_xycb_5c, self.op_xycb_5d, self.op_xycb_5e, self.op_xycb_5f,
            self.op_xycb_60, self.op_xycb_61, self.op_xycb_62, self.op_xycb_63,
            self.op_xycb_64, self.op_xycb_65, self.op_xycb_66, self.op_xycb_67,
            self.op_xycb_68, self.op_xycb_69, self.op_xycb_6a, self.op_xycb_6b,
            self.op_xycb_6c, self.op_xycb_6d, self.op_xycb_6e, self.op_xycb_6f,
            self.op_xycb_70, self.op_xycb_71, self.op_xycb_72, self.op_xycb_73,
            self.op_xycb_74, self.op_xycb_75, self.op_xycb_76, self.op_xycb_77,
            self.op_xycb_78, self.op_xycb_79, self.op_xycb_7a, self.op_xycb_7b,
            self.op_xycb_7c, self.op_xycb_7d, self.op_xycb_7e, self.op_xycb_7f,
            self.op_xycb_80, self.op_xycb_81, self.op_xycb_82, self.op_xycb_83,
            self.op_xycb_84, self.op_xycb_85, self.op_xycb_86, self.op_xycb_87,
            self.op_xycb_88, self.op_xycb_89, self.op_xycb_8a, self.op_xycb_8b,
            self.op_xycb_8c, self.op_xycb_8d, self.op_xycb_8e, self.op_xycb_8f,
            self.op_xycb_90, self.op_xycb_91, self.op_xycb_92, self.op_xycb_93,
            self.op_xycb_94, self.op_xycb_95, self.op_xycb_96, self.op_xycb_97,
            self.op_xycb_98, self.op_xycb_99, self.op_xycb_9a, self.op_xycb_9b,
            self.op_xycb_9c, self.op_xycb_9d, self.op_xycb_9e, self.op_xycb_9f,
            self.op_xycb_a0, self.op_xycb_a1, self.op_xycb_a2, self.op_xycb_a3,
            self.op_xycb_a4, self.op_xycb_a5, self.op_xycb_a6, self.op_xycb_a7,
            self.op_xycb_a8, self.op_xycb_a9, self.op_xycb_aa, self.op_xycb_ab,
            self.op_xycb_ac, self.op_xycb_ad, self.op_xycb_ae, self.op_xycb_af,
            self.op_xycb_b0, self.op_xycb_b1, self.op_xycb_b2, self.op_xycb_b3,
            self.op_xycb_b4, self.op_xycb_b5, self.op_xycb_b6, self.op_xycb_b7,
            self.op_xycb_b8, self.op_xycb_b9, self.op_xycb_ba, self.op_xycb_bb,
            self.op_xycb_bc, self.op_xycb_bd, self.op_xycb_be, self.op_xycb_bf,
            self.op_xycb_c0, self.op_xycb_c1, self.op_xycb_c2, self.op_xycb_c3,
            self.op_xycb_c4, self.op_xycb_c5, self.op_xycb_c6, self.op_xycb_c7,
            self.op_xycb_c8, self.op_xycb_c9, self.op_xycb_ca, self.op_xycb_cb,
            self.op_xycb_cc, self.op_xycb_cd, self.op_xycb_ce, self.op_xycb_cf,
            self.op_xycb_d0, self.op_xycb_d1, self.op_xycb_d2, self.op_xycb_d3,
            self.op_xycb_d4, self.op_xycb_d5, self.op_xycb_d6, self.op_xycb_d7,
            self.op_xycb_d8, self.op_xycb_d9, self.op_xycb_da, self.op_xycb_db,
            self.op_xycb_dc, self.op_xycb_dd, self.op_xycb_de, self.op_xycb_df,
            self.op_xycb_e0, self.op_xycb_e1, self.op_xycb_e2, self.op_xycb_e3,
            self.op_xycb_e4, self.op_xycb_e5, self.op_xycb_e6, self.op_xycb_e7,
            self.op_xycb_e8, self.op_xycb_e9, self.op_xycb_ea, self.op_xycb_eb,
            self.op_xycb_ec, self.op_xycb_ed, self.op_xycb_ee, self.op_xycb_ef,
            self.op_xycb_f0, self.op_xycb_f1, self.op_xycb_f2, self.op_xycb_f3,
            self.op_xycb_f4, self.op_xycb_f5, self.op_xycb_f6, self.op_xycb_f7,
            self.op_xycb_f8, self.op_xycb_f9, self.op_xycb_fa, self.op_xycb_fb,
            self.op_xycb_fc, self.op_xycb_fd, self.op_xycb_fe, self.op_xycb_ff,
        ]
        self.op_dd = [
            self.op_dd_00, self.op_dd_01, self.op_dd_02, self.op_dd_03,
            self.op_dd_04, self.op_dd_05, self.op_dd_06, self.op_dd_07,
            self.op_dd_08, self.op_dd_09, self.op_dd_0a, self.op_dd_0b,
            self.op_dd_0c, self.op_dd_0d, self.op_dd_0e, self.op_dd_0f,
            self.op_dd_10, self.op_dd_11, self.op_dd_12, self.op_dd_13,
            self.op_dd_14, self.op_dd_15, self.op_dd_16, self.op_dd_17,
            self.op_dd_18, self.op_dd_19, self.op_dd_1a, self.op_dd_1b,
            self.op_dd_1c, self.op_dd_1d, self.op_dd_1e, self.op_dd_1f,
            self.op_dd_20, self.op_dd_21, self.op_dd_22, self.op_dd_23,
            self.op_dd_24, self.op_dd_25, self.op_dd_26, self.op_dd_27,
            self.op_dd_28, self.op_dd_29, self.op_dd_2a, self.op_dd_2b,
            self.op_dd_2c, self.op_dd_2d, self.op_dd_2e, self.op_dd_2f,
            self.op_dd_30, self.op_dd_31, self.op_dd_32, self.op_dd_33,
            self.op_dd_34, self.op_dd_35, self.op_dd_36, self.op_dd_37,
            self.op_dd_38, self.op_dd_39, self.op_dd_3a, self.op_dd_3b,
            self.op_dd_3c, self.op_dd_3d, self.op_dd_3e, self.op_dd_3f,
            self.op_dd_40, self.op_dd_41, self.op_dd_42, self.op_dd_43,
            self.op_dd_44, self.op_dd_45, self.op_dd_46, self.op_dd_47,
            self.op_dd_48, self.op_dd_49, self.op_dd_4a, self.op_dd_4b,
            self.op_dd_4c, self.op_dd_4d, self.op_dd_4e, self.op_dd_4f,
            self.op_dd_50, self.op_dd_51, self.op_dd_52, self.op_dd_53,
            self.op_dd_54, self.op_dd_55, self.op_dd_56, self.op_dd_57,
            self.op_dd_58, self.op_dd_59, self.op_dd_5a, self.op_dd_5b,
            self.op_dd_5c, self.op_dd_5d, self.op_dd_5e, self.op_dd_5f,
            self.op_dd_60, self.op_dd_61, self.op_dd_62, self.op_dd_63,
            self.op_dd_64, self.op_dd_65, self.op_dd_66, self.op_dd_67,
            self.op_dd_68, self.op_dd_69, self.op_dd_6a, self.op_dd_6b,
            self.op_dd_6c, self.op_dd_6d, self.op_dd_6e, self.op_dd_6f,
            self.op_dd_70, self.op_dd_71, self.op_dd_72, self.op_dd_73,
            self.op_dd_74, self.op_dd_75, self.op_dd_76, self.op_dd_77,
            self.op_dd_78, self.op_dd_79, self.op_dd_7a, self.op_dd_7b,
            self.op_dd_7c, self.op_dd_7d, self.op_dd_7e, self.op_dd_7f,
            self.op_dd_80, self.op_dd_81, self.op_dd_82, self.op_dd_83,
            self.op_dd_84, self.op_dd_85, self.op_dd_86, self.op_dd_87,
            self.op_dd_88, self.op_dd_89, self.op_dd_8a, self.op_dd_8b,
            self.op_dd_8c, self.op_dd_8d, self.op_dd_8e, self.op_dd_8f,
            self.op_dd_90, self.op_dd_91, self.op_dd_92, self.op_dd_93,
            self.op_dd_94, self.op_dd_95, self.op_dd_96, self.op_dd_97,
            self.op_dd_98, self.op_dd_99, self.op_dd_9a, self.op_dd_9b,
            self.op_dd_9c, self.op_dd_9d, self.op_dd_9e, self.op_dd_9f,
            self.op_dd_a0, self.op_dd_a1, self.op_dd_a2, self.op_dd_a3,
            self.op_dd_a4, self.op_dd_a5, self.op_dd_a6, self.op_dd_a7,
            self.op_dd_a8, self.op_dd_a9, self.op_dd_aa, self.op_dd_ab,
            self.op_dd_ac, self.op_dd_ad, self.op_dd_ae, self.op_dd_af,
            self.op_dd_b0, self.op_dd_b1, self.op_dd_b2, self.op_dd_b3,
            self.op_dd_b4, self.op_dd_b5, self.op_dd_b6, self.op_dd_b7,
            self.op_dd_b8, self.op_dd_b9, self.op_dd_ba, self.op_dd_bb,
            self.op_dd_bc, self.op_dd_bd, self.op_dd_be, self.op_dd_bf,
            self.op_dd_c0, self.op_dd_c1, self.op_dd_c2, self.op_dd_c3,
            self.op_dd_c4, self.op_dd_c5, self.op_dd_c6, self.op_dd_c7,
            self.op_dd_c8, self.op_dd_c9, self.op_dd_ca, self.op_dd_cb,
            self.op_dd_cc, self.op_dd_cd, self.op_dd_ce, self.op_dd_cf,
            self.op_dd_d0, self.op_dd_d1, self.op_dd_d2, self.op_dd_d3,
            self.op_dd_d4, self.op_dd_d5, self.op_dd_d6, self.op_dd_d7,
            self.op_dd_d8, self.op_dd_d9, self.op_dd_da, self.op_dd_db,
            self.op_dd_dc, self.op_dd_dd, self.op_dd_de, self.op_dd_df,
            self.op_dd_e0, self.op_dd_e1, self.op_dd_e2, self.op_dd_e3,
            self.op_dd_e4, self.op_dd_e5, self.op_dd_e6, self.op_dd_e7,
            self.op_dd_e8, self.op_dd_e9, self.op_dd_ea, self.op_dd_eb,
            self.op_dd_ec, self.op_dd_ed, self.op_dd_ee, self.op_dd_ef,
            self.op_dd_f0, self.op_dd_f1, self.op_dd_f2, self.op_dd_f3,
            self.op_dd_f4, self.op_dd_f5, self.op_dd_f6, self.op_dd_f7,
            self.op_dd_f8, self.op_dd_f9, self.op_dd_fa, self.op_dd_fb,
            self.op_dd_fc, self.op_dd_fd, self.op_dd_fe, self.op_dd_ff,
        ]
        self.op_fd = self.op_dd
        self.op_ed = [
            self.op_ed_00, self.op_ed_01, self.op_ed_02, self.op_ed_03,
            self.op_ed_04, self.op_ed_05, self.op_ed_06, self.op_ed_07,
            self.op_ed_08, self.op_ed_09, self.op_ed_0a, self.op_ed_0b,
            self.op_ed_0c, self.op_ed_0d, self.op_ed_0e, self.op_ed_0f,
            self.op_ed_10, self.op_ed_11, self.op_ed_12, self.op_ed_13,
            self.op_ed_14, self.op_ed_15, self.op_ed_16, self.op_ed_17,
            self.op_ed_18, self.op_ed_19, self.op_ed_1a, self.op_ed_1b,
            self.op_ed_1c, self.op_ed_1d, self.op_ed_1e, self.op_ed_1f,
            self.op_ed_20, self.op_ed_21, self.op_ed_22, self.op_ed_23,
            self.op_ed_24, self.op_ed_25, self.op_ed_26, self.op_ed_27,
            self.op_ed_28, self.op_ed_29, self.op_ed_2a, self.op_ed_2b,
            self.op_ed_2c, self.op_ed_2d, self.op_ed_2e, self.op_ed_2f,
            self.op_ed_30, self.op_ed_31, self.op_ed_32, self.op_ed_33,
            self.op_ed_34, self.op_ed_35, self.op_ed_36, self.op_ed_37,
            self.op_ed_38, self.op_ed_39, self.op_ed_3a, self.op_ed_3b,
            self.op_ed_3c, self.op_ed_3d, self.op_ed_3e, self.op_ed_3f,
            self.op_ed_40, self.op_ed_41, self.op_ed_42, self.op_ed_43,
            self.op_ed_44, self.op_ed_45, self.op_ed_46, self.op_ed_47,
            self.op_ed_48, self.op_ed_49, self.op_ed_4a, self.op_ed_4b,
            self.op_ed_4c, self.op_ed_4d, self.op_ed_4e, self.op_ed_4f,
            self.op_ed_50, self.op_ed_51, self.op_ed_52, self.op_ed_53,
            self.op_ed_54, self.op_ed_55, self.op_ed_56, self.op_ed_57,
            self.op_ed_58, self.op_ed_59, self.op_ed_5a, self.op_ed_5b,
            self.op_ed_5c, self.op_ed_5d, self.op_ed_5e, self.op_ed_5f,
            self.op_ed_60, self.op_ed_61, self.op_ed_62, self.op_ed_63,
            self.op_ed_64, self.op_ed_65, self.op_ed_66, self.op_ed_67,
            self.op_ed_68, self.op_ed_69, self.op_ed_6a, self.op_ed_6b,
            self.op_ed_6c, self.op_ed_6d, self.op_ed_6e, self.op_ed_6f,
            self.op_ed_70, self.op_ed_71, self.op_ed_72, self.op_ed_73,
            self.op_ed_74, self.op_ed_75, self.op_ed_76, self.op_ed_77,
            self.op_ed_78, self.op_ed_79, self.op_ed_7a, self.op_ed_7b,
            self.op_ed_7c, self.op_ed_7d, self.op_ed_7e, self.op_ed_7f,
            self.op_ed_80, self.op_ed_81, self.op_ed_82, self.op_ed_83,
            self.op_ed_84, self.op_ed_85, self.op_ed_86, self.op_ed_87,
            self.op_ed_88, self.op_ed_89, self.op_ed_8a, self.op_ed_8b,
            self.op_ed_8c, self.op_ed_8d, self.op_ed_8e, self.op_ed_8f,
            self.op_ed_90, self.op_ed_91, self.op_ed_92, self.op_ed_93,
            self.op_ed_94, self.op_ed_95, self.op_ed_96, self.op_ed_97,
            self.op_ed_98, self.op_ed_99, self.op_ed_9a, self.op_ed_9b,
            self.op_ed_9c, self.op_ed_9d, self.op_ed_9e, self.op_ed_9f,
            self.op_ed_a0, self.op_ed_a1, self.op_ed_a2, self.op_ed_a3,
            self.op_ed_a4, self.op_ed_a5, self.op_ed_a6, self.op_ed_a7,
            self.op_ed_a8, self.op_ed_a9, self.op_ed_aa, self.op_ed_ab,
            self.op_ed_ac, self.op_ed_ad, self.op_ed_ae, self.op_ed_af,
            self.op_ed_b0, self.op_ed_b1, self.op_ed_b2, self.op_ed_b3,
            self.op_ed_b4, self.op_ed_b5, self.op_ed_b6, self.op_ed_b7,
            self.op_ed_b8, self.op_ed_b9, self.op_ed_ba, self.op_ed_bb,
            self.op_ed_bc, self.op_ed_bd, self.op_ed_be, self.op_ed_bf,
            self.op_ed_c0, self.op_ed_c1, self.op_ed_c2, self.op_ed_c3,
            self.op_ed_c4, self.op_ed_c5, self.op_ed_c6, self.op_ed_c7,
            self.op_ed_c8, self.op_ed_c9, self.op_ed_ca, self.op_ed_cb,
            self.op_ed_cc, self.op_ed_cd, self.op_ed_ce, self.op_ed_cf,
            self.op_ed_d0, self.op_ed_d1, self.op_ed_d2, self.op_ed_d3,
            self.op_ed_d4, self.op_ed_d5, self.op_ed_d6, self.op_ed_d7,
            self.op_ed_d8, self.op_ed_d9, self.op_ed_da, self.op_ed_db,
            self.op_ed_dc, self.op_ed_dd, self.op_ed_de, self.op_ed_df,
            self.op_ed_e0, self.op_ed_e1, self.op_ed_e2, self.op_ed_e3,
            self.op_ed_e4, self.op_ed_e5, self.op_ed_e6, self.op_ed_e7,
            self.op_ed_e8, self.op_ed_e9, self.op_ed_ea, self.op_ed_eb,
            self.op_ed_ec, self.op_ed_ed, self.op_ed_ee, self.op_ed_ef,
            self.op_ed_f0, self.op_ed_f1, self.op_ed_f2, self.op_ed_f3,
            self.op_ed_f4, self.op_ed_f5, self.op_ed_f6, self.op_ed_f7,
            self.op_ed_f8, self.op_ed_f9, self.op_ed_fa, self.op_ed_fb,
            self.op_ed_fc, self.op_ed_fd, self.op_ed_fe, self.op_ed_ff,
        ]
        self.op_op = [
            self.op_op_00, self.op_op_01, self.op_op_02, self.op_op_03,
            self.op_op_04, self.op_op_05, self.op_op_06, self.op_op_07,
            self.op_op_08, self.op_op_09, self.op_op_0a, self.op_op_0b,
            self.op_op_0c, self.op_op_0d, self.op_op_0e, self.op_op_0f,
            self.op_op_10, self.op_op_11, self.op_op_12, self.op_op_13,
            self.op_op_14, self.op_op_15, self.op_op_16, self.op_op_17,
            self.op_op_18, self.op_op_19, self.op_op_1a, self.op_op_1b,
            self.op_op_1c, self.op_op_1d, self.op_op_1e, self.op_op_1f,
            self.op_op_20, self.op_op_21, self.op_op_22, self.op_op_23,
            self.op_op_24, self.op_op_25, self.op_op_26, self.op_op_27,
            self.op_op_28, self.op_op_29, self.op_op_2a, self.op_op_2b,
            self.op_op_2c, self.op_op_2d, self.op_op_2e, self.op_op_2f,
            self.op_op_30, self.op_op_31, self.op_op_32, self.op_op_33,
            self.op_op_34, self.op_op_35, self.op_op_36, self.op_op_37,
            self.op_op_38, self.op_op_39, self.op_op_3a, self.op_op_3b,
            self.op_op_3c, self.op_op_3d, self.op_op_3e, self.op_op_3f,
            self.op_op_40, self.op_op_41, self.op_op_42, self.op_op_43,
            self.op_op_44, self.op_op_45, self.op_op_46, self.op_op_47,
            self.op_op_48, self.op_op_49, self.op_op_4a, self.op_op_4b,
            self.op_op_4c, self.op_op_4d, self.op_op_4e, self.op_op_4f,
            self.op_op_50, self.op_op_51, self.op_op_52, self.op_op_53,
            self.op_op_54, self.op_op_55, self.op_op_56, self.op_op_57,
            self.op_op_58, self.op_op_59, self.op_op_5a, self.op_op_5b,
            self.op_op_5c, self.op_op_5d, self.op_op_5e, self.op_op_5f,
            self.op_op_60, self.op_op_61, self.op_op_62, self.op_op_63,
            self.op_op_64, self.op_op_65, self.op_op_66, self.op_op_67,
            self.op_op_68, self.op_op_69, self.op_op_6a, self.op_op_6b,
            self.op_op_6c, self.op_op_6d, self.op_op_6e, self.op_op_6f,
            self.op_op_70, self.op_op_71, self.op_op_72, self.op_op_73,
            self.op_op_74, self.op_op_75, self.op_op_76, self.op_op_77,
            self.op_op_78, self.op_op_79, self.op_op_7a, self.op_op_7b,
            self.op_op_7c, self.op_op_7d, self.op_op_7e, self.op_op_7f,
            self.op_op_80, self.op_op_81, self.op_op_82, self.op_op_83,
            self.op_op_84, self.op_op_85, self.op_op_86, self.op_op_87,
            self.op_op_88, self.op_op_89, self.op_op_8a, self.op_op_8b,
            self.op_op_8c, self.op_op_8d, self.op_op_8e, self.op_op_8f,
            self.op_op_90, self.op_op_91, self.op_op_92, self.op_op_93,
            self.op_op_94, self.op_op_95, self.op_op_96, self.op_op_97,
            self.op_op_98, self.op_op_99, self.op_op_9a, self.op_op_9b,
            self.op_op_9c, self.op_op_9d, self.op_op_9e, self.op_op_9f,
            self.op_op_a0, self.op_op_a1, self.op_op_a2, self.op_op_a3,
            self.op_op_a4, self.op_op_a5, self.op_op_a6, self.op_op_a7,
            self.op_op_a8, self.op_op_a9, self.op_op_aa, self.op_op_ab,
            self.op_op_ac, self.op_op_ad, self.op_op_ae, self.op_op_af,
            self.op_op_b0, self.op_op_b1, self.op_op_b2, self.op_op_b3,
            self.op_op_b4, self.op_op_b5, self.op_op_b6, self.op_op_b7,
            self.op_op_b8, self.op_op_b9, self.op_op_ba, self.op_op_bb,
            self.op_op_bc, self.op_op_bd, self.op_op_be, self.op_op_bf,
            self.op_op_c0, self.op_op_c1, self.op_op_c2, self.op_op_c3,
            self.op_op_c4, self.op_op_c5, self.op_op_c6, self.op_op_c7,
            self.op_op_c8, self.op_op_c9, self.op_op_ca, self.op_op_cb,
            self.op_op_cc, self.op_op_cd, self.op_op_ce, self.op_op_cf,
            self.op_op_d0, self.op_op_d1, self.op_op_d2, self.op_op_d3,
            self.op_op_d4, self.op_op_d5, self.op_op_d6, self.op_op_d7,
            self.op_op_d8, self.op_op_d9, self.op_op_da, self.op_op_db,
            self.op_op_dc, self.op_op_dd, self.op_op_de, self.op_op_df,
            self.op_op_e0, self.op_op_e1, self.op_op_e2, self.op_op_e3,
            self.op_op_e4, self.op_op_e5, self.op_op_e6, self.op_op_e7,
            self.op_op_e8, self.op_op_e9, self.op_op_ea, self.op_op_eb,
            self.op_op_ec, self.op_op_ed, self.op_op_ee, self.op_op_ef,
            self.op_op_f0, self.op_op_f1, self.op_op_f2, self.op_op_f3,
            self.op_op_f4, self.op_op_f5, self.op_op_f6, self.op_op_f7,
            self.op_op_f8, self.op_op_f9, self.op_op_fa, self.op_op_fb,
            self.op_op_fc, self.op_op_fd, self.op_op_fe, self.op_op_ff,
        ]
    
