; binary: libnvram.so
; function: file_to_buf
; symbol: file_to_buf
; entry_ea: 0x11d0
; source_sha256: 6e90b0a95384f6ced071e1ee1d0aefcc3ccc0ef07074ccf142073d9d07de418f
; chunk: 0x11d0-0x12a0
0x000011d0:  05 00 1c 3c 70 a4 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x000011d8:  21 e0 99 03              addu    $gp, $t9
0x000011dc:  d8 ff bd 27              addiu   $sp, -0x28
0x000011e0:  24 00 bf af              sw      $ra, 0x18+var_sC($sp)
0x000011e4:  20 00 b2 af              sw      $s2, 0x18+var_s8($sp)
0x000011e8:  1c 00 b1 af              sw      $s1, 0x18+var_s4($sp)
0x000011ec:  18 00 b0 af              sw      $s0, 0x18+var_s0($sp)
0x000011f0:  10 00 bc af              sw      $gp, 0x18+var_8($sp)
0x000011f4:  64 80 99 8f              la      $t9, memset
0x000011f8:  21 88 a0 00              move    $s1, $a1
0x000011fc:  21 80 80 00              move    $s0, $a0
0x00001200:  21 28 00 00              move    $a1, $zero
0x00001204:  21 20 20 02              move    $a0, $s1
0x00001208:  09 f8 20 03              jalr    $t9  # memset
0x0000120c:  21 90 c0 00              move    $s2, $a2
0x00001210:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001214:  21 20 00 02              move    $a0, $s0
0x00001218:  18 80 85 8f              li      $a1, 0
0x0000121c:  6c 80 99 8f              la      $t9, fopen
0x00001220:  00 00 00 00              nop
0x00001224:  09 f8 20 03              jalr    $t9  # fopen
0x00001228:  e4 2c a5 24              addiu   $a1, (aWl0RadiusIpadd+0x10) # "r"
0x0000122c:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001230:  14 00 40 10              beqz    $v0, loc_1284
0x00001234:  21 80 40 00              move    $s0, $v0
0x00001238:  a0 80 99 8f              la      $t9, fgets
0x0000123c:  21 28 40 02              move    $a1, $s2
0x00001240:  21 20 20 02              move    $a0, $s1
0x00001244:  09 f8 20 03              jalr    $t9  # fgets
0x00001248:  21 30 40 00              move    $a2, $v0
0x0000124c:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001250:  00 00 00 00              nop
0x00001254:  60 80 99 8f              la      $t9, fclose
0x00001258:  00 00 00 00              nop
0x0000125c:  09 f8 20 03              jalr    $t9  # fclose
0x00001260:  21 20 00 02              move    $a0, $s0
0x00001264:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001268:  24 00 bf 8f              lw      $ra, 0x18+var_sC($sp)
0x0000126c:  20 00 b2 8f              lw      $s2, 0x18+var_s8($sp)
0x00001270:  1c 00 b1 8f              lw      $s1, 0x18+var_s4($sp)
0x00001274:  18 00 b0 8f              lw      $s0, 0x18+var_s0($sp)
0x00001278:  01 00 02 24              li      $v0, 1
0x0000127c:  08 00 e0 03              jr      $ra
0x00001280:  28 00 bd 27              addiu   $sp, 0x28
0x00001284:  24 00 bf 8f              lw      $ra, 0x18+var_sC($sp)
0x00001288:  20 00 b2 8f              lw      $s2, 0x18+var_s8($sp)
0x0000128c:  1c 00 b1 8f              lw      $s1, 0x18+var_s4($sp)
0x00001290:  18 00 b0 8f              lw      $s0, 0x18+var_s0($sp)
0x00001294:  21 10 00 00              move    $v0, $zero
0x00001298:  08 00 e0 03              jr      $ra
0x0000129c:  28 00 bd 27              addiu   $sp, 0x28
