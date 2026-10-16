; binary: ntpclient
; function: stuff_net_addr6
; symbol: stuff_net_addr6
; entry_ea: 0x4019c4
; source_sha256: bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2
; chunk: 0x4019c4-0x401a90
0x004019c4:  05 00 1c 3c 7c c6 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x004019cc:  21 e0 99 03              addu    $gp, $t9
0x004019d0:  d8 ff bd 27              addiu   $sp, -0x28
0x004019d4:  20 00 bf af              sw      $ra, 0x18+var_s8($sp)
0x004019d8:  1c 00 b1 af              sw      $s1, 0x18+var_s4($sp)
0x004019dc:  18 00 b0 af              sw      $s0, 0x18+var_s0($sp)
0x004019e0:  10 00 bc af              sw      $gp, 0x18+var_8($sp)
0x004019e4:  21 80 80 00              move    $s0, $a0
0x004019e8:  21 88 a0 00              move    $s1, $a1
0x004019ec:  21 20 a0 00              move    $a0, $a1 # name
0x004019f0:  64 80 99 8f              la      $t9, gethostbyname2
0x004019f4:  00 00 00 00              nop
0x004019f8:  09 f8 20 03              jalr    $t9  # gethostbyname2
0x004019fc:  0a 00 05 24              li      $a1, 0xA # af
0x00401a00:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00401a04:  08 00 40 14              bnez    $v0, loc_401A28
0x00401a08:  00 00 00 00              nop
0x00401a0c:  ac 80 99 8f              la      $t9, herror
0x00401a10:  00 00 00 00              nop
0x00401a14:  09 f8 20 03              jalr    $t9  # herror
0x00401a18:  21 20 20 02              move    $a0, $s1 # str
0x00401a1c:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00401a20:  16 00 00 10              b       loc_401A7C
0x00401a24:  01 00 02 24              li      $v0, 1
0x00401a28:  10 00 42 8c              lw      $v0, 0x10($v0)
0x00401a2c:  00 00 00 00              nop
0x00401a30:  00 00 42 8c              lw      $v0, 0($v0)
0x00401a34:  00 00 00 00              nop
0x00401a38:  03 00 46 88              lwl     $a2, 3($v0)
0x00401a3c:  00 00 00 00              nop
0x00401a40:  00 00 46 98              lwr     $a2, 0($v0)
0x00401a44:  07 00 45 88              lwl     $a1, 7($v0)
0x00401a48:  00 00 00 00              nop
0x00401a4c:  04 00 45 98              lwr     $a1, 4($v0)
0x00401a50:  0b 00 44 88              lwl     $a0, 0xB($v0)
0x00401a54:  00 00 00 00              nop
0x00401a58:  08 00 44 98              lwr     $a0, 8($v0)
0x00401a5c:  0f 00 43 88              lwl     $v1, 0xF($v0)
0x00401a60:  00 00 00 00              nop
0x00401a64:  0c 00 43 98              lwr     $v1, 0xC($v0)
0x00401a68:  00 00 06 ae              sw      $a2, 0($s0)
0x00401a6c:  04 00 05 ae              sw      $a1, 4($s0)
0x00401a70:  08 00 04 ae              sw      $a0, 8($s0)
0x00401a74:  0c 00 03 ae              sw      $v1, 0xC($s0)
0x00401a78:  21 10 00 00              move    $v0, $zero
0x00401a7c:  20 00 bf 8f              lw      $ra, 0x18+var_s8($sp)
0x00401a80:  1c 00 b1 8f              lw      $s1, 0x18+var_s4($sp)
0x00401a84:  18 00 b0 8f              lw      $s0, 0x18+var_s0($sp)
0x00401a88:  08 00 e0 03              jr      $ra
0x00401a8c:  28 00 bd 27              addiu   $sp, 0x28
