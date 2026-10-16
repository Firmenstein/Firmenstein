; binary: nvram
; function: nvram_getall
; symbol: .nvram_getall
; entry_ea: 0x400d30
; source_sha256: 690e220908417414f4b4b003811dda7b4f380c14eb9ec0657744bda44913c33d
; chunk: 0x400d30-0x400d40
0x00400d30:  10 80 99 8f  lw      $t9, _GLOBAL_OFFSET_TABLE_
0x00400d34:  21 78 e0 03  move    $t7, $ra
0x00400d38:  09 f8 20 03  jalr    $t9
0x00400d3c:  20 00 18 24  li      $t8, 0x20  # ' '
