; binary: nvram
; function: nvram_get
; symbol: .nvram_get
; entry_ea: 0x400d90
; source_sha256: 690e220908417414f4b4b003811dda7b4f380c14eb9ec0657744bda44913c33d
; chunk: 0x400d90-0x400da0
0x00400d90:  10 80 99 8f  lw      $t9, _GLOBAL_OFFSET_TABLE_
0x00400d94:  21 78 e0 03  move    $t7, $ra
0x00400d98:  09 f8 20 03  jalr    $t9
0x00400d9c:  16 00 18 24  li      $t8, 0x16
