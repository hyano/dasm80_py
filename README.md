# dasm80_py

This is a simple Z80 disassembler written in Python.

## Usage

```shell-session
$ python3 dasm80.py -h
usage: dasm80 [-h] [-l LABEL] [-s START] [-e ENTRY] filename

Z80 disassembler

positional arguments:
  filename

options:
  -h, --help            show this help message and exit
  -l LABEL, --label LABEL
                        label filename
  -s START, --start START
                        start address
  -e ENTRY, --entry ENTRY
                        entry address
  --label-prefix LABEL_PREFIX
                        label prefix
  --enable-address      enable address output
  --enable-patch ID     enable patch id
  --enable-delete ID    enable delete id
```

## Label file

| command               | description                                               |
| --------------------- | --------------------------------------------------------- | 
| c addr                | code                                                      |
| b addr count [width]  | byte data                                                 |
| w addr count [width]  | word data                                                 |
| t addr count          | jump table                                                |
| n addr count          | data table                                                |
| n addr                | disable labeling                                          |
| r0 addr comment       | insert comment before label                               |
| r1 addr comment       | insert comment after label                                |
| r2 addr comment       | insert comment after instruction                          |
| r addr comment        | same as r0                                                |
| p0 addr id patch      | insert patch before label (--enable-patch required)       |
| p1 addr id patch      | insert patch after label  (--enable-patch required)       |
| p2 addr id patch      | insert patch after instruction  (--enable-patch required) |
| p addr id patch       | same as p0                                                |
| d start end           | delete code from start to end-1                           |

* addr, count, width are hexadecimal format.
* id is decimal format.
* if count is 0, it continues to next label.
* default width is 10 for byte, 8 for word. 

## License
This software is released under [MIT License](LICENSE).
Copyright (c) 2023 Hirokuni Yano
