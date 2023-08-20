#!/usr/bin/env python3
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
    fh = open(label_file, "r")
    for line in fh:
        dasm.label_command(line.rstrip("\n"))
    fh.close()

def main():
    def hex_int(x):
        return int(x, 16)

    parser = argparse.ArgumentParser(
        prog = "dasm80",
        description = "Z80 disassembler"
    )
    parser.add_argument("filename")
    parser.add_argument("-l", "--label", help="label filename")
    parser.add_argument("-s", "--start", help="start address", default = 0x0000, type=hex_int)
    parser.add_argument("-e", "--entry", help="entry address", default = 0x0000, type=hex_int)
    parser.add_argument("--label-prefix", dest="label_prefix", help="label prefix")
    parser.add_argument("--enable-patch", dest="enable_patch", help="enable patch feature", action="store_true")
    parser.add_argument("--enable-address", dest="enable_address", help="enable address output", action="store_true")
    args = parser.parse_args()

    membus = Bus(mem_read, mem_write)
    dasm = Z80dasm(membus, print)

    label_file = args.label
    start_addr = args.start
    entry_addr = args.entry

    if args.label_prefix:
        dasm.config_label_prefix(args.label_prefix)
    if args.enable_patch:
        dasm.config_enable_patch(True)
    if args.enable_address:
        dasm.config_enable_address(True)

    fh = open(args.filename, "rb")
    addr = start_addr
    for b in fh.read():
        data[addr] = int(b)
        addr += 1
    fh.close()
    end_addr = addr

    if label_file:
        load_label_file(dasm, label_file)
    
    dasm.disassemble(start_addr, end_addr, entry_addr)

if __name__ == "__main__":
    main()
