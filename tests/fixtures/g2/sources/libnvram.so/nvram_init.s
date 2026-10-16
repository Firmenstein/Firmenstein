; binary: libnvram.so
; function: nvram_init
; symbol: nvram_init
; entry_ea: 0x16f4
; source_sha256: 6e90b0a95384f6ced071e1ee1d0aefcc3ccc0ef07074ccf142073d9d07de418f
; chunk: 0x16f4-0x17f4
0x000016f4:  05 00 1c 3c 4c 9f 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x000016fc:  21 e0 99 03              addu    $gp, $t9
0x00001700:  d0 ff bd 27              addiu   $sp, -0x30
0x00001704:  2c 00 bf af              sw      $ra, 0x20+var_sC($sp)
0x00001708:  28 00 b2 af              sw      $s2, 0x20+var_s8($sp)
0x0000170c:  24 00 b1 af              sw      $s1, 0x20+var_s4($sp)
0x00001710:  20 00 b0 af              sw      $s0, 0x20+var_s0($sp)
0x00001714:  18 00 bc af              sw      $gp, 0x20+var_8($sp)
0x00001718:  1c 80 91 8f              li      $s1, 0x40000
0x0000171c:  00 00 00 00              nop
0x00001720:  90 31 22 8e              lw      $v0, (_fdata - 0x40000)($s1)
0x00001724:  00 00 00 00              nop
0x00001728:  08 00 40 04              bltz    $v0, loc_174C
0x0000172c:  00 00 00 00              nop
0x00001730:  21 10 00 00              move    $v0, $zero
0x00001734:  2c 00 bf 8f              lw      $ra, 0x20+var_sC($sp)
0x00001738:  28 00 b2 8f              lw      $s2, 0x20+var_s8($sp)
0x0000173c:  24 00 b1 8f              lw      $s1, 0x20+var_s4($sp)
0x00001740:  20 00 b0 8f              lw      $s0, 0x20+var_s0($sp)
0x00001744:  08 00 e0 03              jr      $ra
0x00001748:  30 00 bd 27              addiu   $sp, 0x30
0x0000174c:  18 80 92 8f              li      $s2, 0
0x00001750:  3c 80 99 8f              la      $t9, open
0x00001754:  70 28 44 26              addiu   $a0, $s2, aDevNvram # "/dev/nvram"
0x00001758:  09 f8 20 03              jalr    $t9  # open
0x0000175c:  02 00 05 24              li      $a1, 2
0x00001760:  18 00 bc 8f              lw      $gp, 0x20+var_8($sp)
0x00001764:  15 00 40 04              bltz    $v0, loc_17BC
0x00001768:  90 31 22 ae              sw      $v0, (_fdata - 0x40000)($s1)
0x0000176c:  8c 80 99 8f              la      $t9, mmap
0x00001770:  10 00 a2 af              sw      $v0, 0x20+var_10($sp)
0x00001774:  14 00 a0 af              sw      $zero, 0x20+var_C($sp)
0x00001778:  21 20 00 00              move    $a0, $zero
0x0000177c:  00 f0 05 34              li      $a1, 0xF000
0x00001780:  01 00 06 24              li      $a2, 1
0x00001784:  09 f8 20 03              jalr    $t9  # mmap
0x00001788:  01 00 07 24              li      $a3, 1
0x0000178c:  18 00 bc 8f              lw      $gp, 0x20+var_8($sp)
0x00001790:  21 80 40 00              move    $s0, $v0
0x00001794:  1c 80 82 8f              li      $v0, 0x40000
0x00001798:  ff ff 03 24              li      $v1, 0xFFFFFFFF
0x0000179c:  e4 ff 03 16              bne     $s0, $v1, loc_1730
0x000017a0:  f0 36 50 ac              sw      $s0, (dword_436F0 - 0x40000)($v0)
0x000017a4:  30 80 99 8f              la      $t9, close
0x000017a8:  90 31 24 8e              lw      $a0, (_fdata - 0x40000)($s1)
0x000017ac:  09 f8 20 03              jalr    $t9  # close
0x000017b0:  00 00 00 00              nop
0x000017b4:  18 00 bc 8f              lw      $gp, 0x20+var_8($sp)
0x000017b8:  90 31 30 ae              sw      $s0, (_fdata - 0x40000)($s1)
0x000017bc:  9c 80 99 8f              la      $t9, perror
0x000017c0:  00 00 00 00              nop
0x000017c4:  09 f8 20 03              jalr    $t9  # perror
0x000017c8:  70 28 44 26              addiu   $a0, $s2, aDevNvram # "/dev/nvram"
0x000017cc:  18 00 bc 8f              lw      $gp, 0x20+var_8($sp)
0x000017d0:  00 00 00 00              nop
0x000017d4:  48 80 99 8f              la      $t9, __errno_location
0x000017d8:  00 00 00 00              nop
0x000017dc:  09 f8 20 03              jalr    $t9  # __errno_location
0x000017e0:  00 00 00 00              nop
0x000017e4:  00 00 42 8c              lw      $v0, 0($v0)
0x000017e8:  18 00 bc 8f              lw      $gp, 0x20+var_8($sp)
0x000017ec:  d1 ff 00 10              b       loc_1734
0x000017f0:  00 00 00 00              nop
