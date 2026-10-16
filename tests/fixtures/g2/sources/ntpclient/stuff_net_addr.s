; binary: ntpclient
; function: stuff_net_addr
; symbol: stuff_net_addr
; entry_ea: 0x401a90
; source_sha256: bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2
; chunk: 0x401a90-0x401b68
0x00401a90:  05 00 1c 3c b0 c5 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x00401a98:  21 e0 99 03              addu    $gp, $t9
0x00401a9c:  d8 ff bd 27              addiu   $sp, -0x28
0x00401aa0:  20 00 bf af              sw      $ra, 0x18+var_s8($sp)
0x00401aa4:  1c 00 b1 af              sw      $s1, 0x18+var_s4($sp)
0x00401aa8:  18 00 b0 af              sw      $s0, 0x18+var_s0($sp)
0x00401aac:  10 00 bc af              sw      $gp, 0x18+var_8($sp)
0x00401ab0:  21 88 80 00              move    $s1, $a0
0x00401ab4:  21 80 a0 00              move    $s0, $a1
0x00401ab8:  a0 80 99 8f              la      $t9, gethostbyname
0x00401abc:  00 00 00 00              nop
0x00401ac0:  09 f8 20 03              jalr    $t9  # gethostbyname
0x00401ac4:  21 20 a0 00              move    $a0, $a1 # name
0x00401ac8:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00401acc:  08 00 40 14              bnez    $v0, loc_401AF0
0x00401ad0:  21 18 40 00              move    $v1, $v0
0x00401ad4:  ac 80 99 8f              la      $t9, herror
0x00401ad8:  00 00 00 00              nop
0x00401adc:  09 f8 20 03              jalr    $t9  # herror
0x00401ae0:  21 20 00 02              move    $a0, $s0 # str
0x00401ae4:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00401ae8:  1a 00 00 10              b       loc_401B54
0x00401aec:  01 00 02 24              li      $v0, 1
0x00401af0:  0c 00 46 8c              lw      $a2, 0xC($v0)
0x00401af4:  04 00 02 24              li      $v0, 4
0x00401af8:  0c 00 c2 10              beq     $a2, $v0, loc_401B2C
0x00401afc:  00 00 00 00              nop
0x00401b00:  90 80 82 8f              la      $v0, stderr
0x00401b04:  00 00 00 00              nop
0x00401b08:  00 00 44 8c              lw      $a0, (stderr - 0x446E8C)($v0) # stream
0x00401b0c:  1c 80 85 8f              li      $a1, 0x400000
0x00401b10:  2c 81 99 8f              la      $t9, fprintf
0x00401b14:  00 00 00 00              nop
0x00401b18:  09 f8 20 03              jalr    $t9  # fprintf
0x00401b1c:  78 55 a5 24              addiu   $a1, (aOopsD - 0x400000) # "oops %d\n"
0x00401b20:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00401b24:  0b 00 00 10              b       loc_401B54
0x00401b28:  01 00 02 24              li      $v0, 1
0x00401b2c:  10 00 62 8c              lw      $v0, 0x10($v1)
0x00401b30:  00 00 00 00              nop
0x00401b34:  00 00 42 8c              lw      $v0, 0($v0)
0x00401b38:  00 00 00 00              nop
0x00401b3c:  03 00 43 88              lwl     $v1, 3($v0)
0x00401b40:  00 00 00 00              nop
0x00401b44:  00 00 43 98              lwr     $v1, 0($v0)
0x00401b48:  00 00 00 00              nop
0x00401b4c:  00 00 23 ae              sw      $v1, 0($s1)
0x00401b50:  21 10 00 00              move    $v0, $zero
0x00401b54:  20 00 bf 8f              lw      $ra, 0x18+var_s8($sp)
0x00401b58:  1c 00 b1 8f              lw      $s1, 0x18+var_s4($sp)
0x00401b5c:  18 00 b0 8f              lw      $s0, 0x18+var_s0($sp)
0x00401b60:  08 00 e0 03              jr      $ra
0x00401b64:  28 00 bd 27              addiu   $sp, 0x28
