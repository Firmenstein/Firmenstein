; binary: libnvram.so
; function: nvram_getall
; symbol: nvram_getall
; entry_ea: 0x2080
; source_sha256: 6e90b0a95384f6ced071e1ee1d0aefcc3ccc0ef07074ccf142073d9d07de418f
; chunk: 0x2080-0x2150
0x00002080:  05 00 1c 3c c0 95 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x00002088:  21 e0 99 03              addu    $gp, $t9
0x0000208c:  d8 ff bd 27              addiu   $sp, -0x28
0x00002090:  24 00 bf af              sw      $ra, 0x18+var_sC($sp)
0x00002094:  20 00 b2 af              sw      $s2, 0x18+var_s8($sp)
0x00002098:  1c 00 b1 af              sw      $s1, 0x18+var_s4($sp)
0x0000209c:  18 00 b0 af              sw      $s0, 0x18+var_s0($sp)
0x000020a0:  10 00 bc af              sw      $gp, 0x18+var_8($sp)
0x000020a4:  38 80 99 8f              la      $t9, nvram_init
0x000020a8:  21 88 80 00              move    $s1, $a0
0x000020ac:  21 20 00 00              move    $a0, $zero
0x000020b0:  09 f8 20 03              jalr    $t9  # nvram_init
0x000020b4:  21 90 a0 00              move    $s2, $a1
0x000020b8:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x000020bc:  03 00 40 14              bnez    $v0, loc_20CC
0x000020c0:  21 80 40 00              move    $s0, $v0
0x000020c4:  08 00 40 16              bnez    $s2, loc_20E8
0x000020c8:  21 28 20 02              move    $a1, $s1
0x000020cc:  21 10 00 02              move    $v0, $s0
0x000020d0:  24 00 bf 8f              lw      $ra, 0x18+var_sC($sp)
0x000020d4:  20 00 b2 8f              lw      $s2, 0x18+var_s8($sp)
0x000020d8:  1c 00 b1 8f              lw      $s1, 0x18+var_s4($sp)
0x000020dc:  18 00 b0 8f              lw      $s0, 0x18+var_s0($sp)
0x000020e0:  08 00 e0 03              jr      $ra
0x000020e4:  28 00 bd 27              addiu   $sp, 0x28
0x000020e8:  1c 80 82 8f              li      $v0, 0x40000
0x000020ec:  00 00 20 a2              sb      $zero, 0($s1)
0x000020f0:  7c 80 99 8f              la      $t9, read
0x000020f4:  90 31 44 8c              lw      $a0, (_fdata - 0x40000)($v0)
0x000020f8:  09 f8 20 03              jalr    $t9  # read
0x000020fc:  21 30 40 02              move    $a2, $s2
0x00002100:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00002104:  0a 00 40 04              bltz    $v0, loc_2130
0x00002108:  21 88 40 00              move    $s1, $v0
0x0000210c:  ef ff 51 12              beq     $s2, $s1, loc_20CC
0x00002110:  21 10 20 02              move    $v0, $s1
0x00002114:  21 80 20 02              move    $s0, $s1
0x00002118:  24 00 bf 8f              lw      $ra, 0x18+var_sC($sp)
0x0000211c:  20 00 b2 8f              lw      $s2, 0x18+var_s8($sp)
0x00002120:  1c 00 b1 8f              lw      $s1, 0x18+var_s4($sp)
0x00002124:  18 00 b0 8f              lw      $s0, 0x18+var_s0($sp)
0x00002128:  08 00 e0 03              jr      $ra
0x0000212c:  28 00 bd 27              addiu   $sp, 0x28
0x00002130:  18 80 84 8f              li      $a0, 0
0x00002134:  9c 80 99 8f              la      $t9, perror
0x00002138:  00 00 00 00              nop
0x0000213c:  09 f8 20 03              jalr    $t9  # perror
0x00002140:  70 28 84 24              addiu   $a0, aDevNvram # "/dev/nvram"
0x00002144:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00002148:  f0 ff 00 10              b       loc_210C
0x0000214c:  00 00 00 00              nop
