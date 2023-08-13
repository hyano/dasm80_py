# -*- coding: utf-8 -*-
# Copyright (c) 2023 Hirokuni Yano
#
# Released under the MIT license.
# see https://opensource.org/licenses/MIT
#

import argparse
from Z80dasm import Z80dasm, Bus


data = [0] * 0x10000

def mem_read(addr):
    res = data[addr]
    #print("MR: {:04x}: {:02x}".format(addr, res))
    return res

def mem_write(addr, data):
    #print("MW: {:04x}: {:02x}".format(addr, data))
    pass

def load_label_file(dasm, label_file):
    fh = open(label_file, 'r')
    for line in fh:
        l = line.rstrip('\n').split(" ")
        if (l[0] == 'c'):
            addr = int(l[1], 16)
            dasm.set_code(addr)
            dasm.set_label(addr)
        elif (l[0] == 'b'):
            addr = int(l[1], 16)
            count = int(l[2], 16)
            dasm.set_byte(addr, count)
            dasm.set_label(addr)
        elif (l[0] == 'w'):
            addr = int(l[1], 16)
            count = int(l[2], 16)
            dasm.set_word(addr, count)
            dasm.set_label(addr)
        elif (l[0] == 't'):
            addr = int(l[1], 16)
            count = int(l[2], 16)
            dasm.set_jp_table(addr, count)
            dasm.set_label(addr)
        elif (l[0] == 'u'):
            addr = int(l[1], 16)
            count = int(l[2], 16)
            dasm.set_dt_table(addr, count)
            dasm.set_label(addr)
        elif (l[0] == 'n'):
            addr = int(l[1], 16)
            dasm.set_no_label(addr)
    fh.close()

def main():
    def hex_int(x):
        return int(x, 16)

    parser = argparse.ArgumentParser(
        prog = 'dasm80',
        description = 'Z80 disassembler'
    )
    parser.add_argument('filename')
    parser.add_argument('-l', '--label', help='label filename')
    parser.add_argument('-s', '--start', help='start address', default = 0x0000, type=hex_int)
    parser.add_argument('-e', '--entry', help='entry address', default = 0x0000, type=hex_int)
    args = parser.parse_args()

    membus = Bus(mem_read, mem_write)
    dasm = Z80dasm(membus, print)

    label_file = args.label
    start_addr = args.start
    entry_addr = args.entry

    fh = open(args.filename, 'rb')
    addr = start_addr
    for b in fh.read():
        data[addr] = int(b)
        addr += 1
    fh.close()
    end_addr = addr

    if label_file:
        load_label_file(dasm, label_file)

    dasm.disassemble(start_addr, end_addr, entry_addr)

if __name__ == '__main__':
    main()
