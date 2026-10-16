; binary: nvram
; function: usage
; symbol: usage
; entry_ea: 0x400910
; source_sha256: 690e220908417414f4b4b003811dda7b4f380c14eb9ec0657744bda44913c33d
; chunk: 0x400910-0x400960
0x00400910:  05 00 1c 3c 40 86 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x00400918:  21 e0 99 03              addu    $gp, $t9
0x0040091c:  e0 ff bd 27              addiu   $sp, -0x20
0x00400920:  18 00 bf af              sw      $ra, 0x18+var_s0($sp)
0x00400924:  10 00 bc af              sw      $gp, 0x18+var_8($sp)
0x00400928:  44 80 82 8f              la      $v0, stderr
0x0040092c:  1c 80 84 8f              li      $a0, 0x400000
0x00400930:  3c 80 99 8f              la      $t9, fwrite
0x00400934:  00 00 47 8c              lw      $a3, (stderr - 0x441034)($v0) # s
0x00400938:  78 0e 84 24              addiu   $a0, (aUsageNvramGetN - 0x400000) # "usage: nvram [get name] [set name=value"...
0x0040093c:  01 00 05 24              li      $a1, 1 # size
0x00400940:  09 f8 20 03              jalr    $t9  # fwrite
0x00400944:  4a 00 06 24              li      $a2, 0x4A  # 'J' # n
0x00400948:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x0040094c:  00 00 00 00              nop
0x00400950:  38 80 99 8f              la      $t9, exit
0x00400954:  00 00 00 00              nop
0x00400958:  09 f8 20 03              jalr    $t9  # exit
0x0040095c:  21 20 00 00              move    $a0, $zero # status
