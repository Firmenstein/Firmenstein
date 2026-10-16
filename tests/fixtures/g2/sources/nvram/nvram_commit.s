; binary: nvram
; function: nvram_commit
; symbol: .nvram_commit
; entry_ea: 0x400db0
; source_sha256: 690e220908417414f4b4b003811dda7b4f380c14eb9ec0657744bda44913c33d
; chunk: 0x400db0-0x400dc0
0x00400db0:  10 80 99 8f  lw      $t9, _GLOBAL_OFFSET_TABLE_
0x00400db4:  21 78 e0 03  move    $t7, $ra
0x00400db8:  09 f8 20 03  jalr    $t9
0x00400dbc:  13 00 18 24  li      $t8, 0x13
