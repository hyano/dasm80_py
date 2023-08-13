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
```

## Label file

| command       | description             |
| ------------- | ----------------------- | 
| c addr        | code                    |
| b addr count  | byte data               |
| w addr count  | word data               |
| t addr count  | jump table              |
| n addr count  | data table              |
| n addr        | disable labeling        |

addr, size are hexadecimal format

## License
This software is released under [MIT License](LICENSE).
Copyright (c) 2023 Hirokuni Yano
