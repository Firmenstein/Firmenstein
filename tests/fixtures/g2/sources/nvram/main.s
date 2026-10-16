; binary: nvram
; function: main
; symbol: main
; entry_ea: 0x400960
; source_sha256: 690e220908417414f4b4b003811dda7b4f380c14eb9ec0657744bda44913c33d
; chunk: 0x400960-0x400cc4
0x00400960:  05 00 1c 3c f0 85 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x00400968:  21 e0 99 03              addu    $gp, $t9
0x0040096c:  10 80 bd 27              addiu   $sp, -0x7FF0
0x00400970:  ec 7f bf af              sw      $ra, 0x7FC8+var_s24($sp)
0x00400974:  e8 7f be af              sw      $fp, 0x7FC8+var_s20($sp)
0x00400978:  e4 7f b7 af              sw      $s7, 0x7FC8+var_s1C($sp)
0x0040097c:  e0 7f b6 af              sw      $s6, 0x7FC8+var_s18($sp)
0x00400980:  dc 7f b5 af              sw      $s5, 0x7FC8+var_s14($sp)
0x00400984:  d8 7f b4 af              sw      $s4, 0x7FC8+var_s10($sp)
0x00400988:  d4 7f b3 af              sw      $s3, 0x7FC8+var_sC($sp)
0x0040098c:  d0 7f b2 af              sw      $s2, 0x7FC8+var_s8($sp)
0x00400990:  cc 7f b1 af              sw      $s1, 0x7FC8+var_s4($sp)
0x00400994:  c8 7f b0 af              sw      $s0, 0x7FC8+var_s0($sp)
0x00400998:  a8 8f bd 27              addiu   $sp, -0x7058
0x0040099c:  10 00 bc af              sw      $gp, 0xF020+var_F010($sp)
0x004009a0:  04 00 b0 8c              lw      $s0, 4($a1)
0x004009a4:  21 88 a0 00              move    $s1, $a1
0x004009a8:  b4 00 00 12              beqz    $s0, loc_400C7C
0x004009ac:  04 00 b2 24              addiu   $s2, $a1, 4
0x004009b0:  1c 00 b3 27              addiu   $s3, $sp, 0xF020+dest
0x004009b4:  14 00 02 24              li      $v0, 0x14
0x004009b8:  1c 80 94 8f              li      $s4, 0x400000
0x004009bc:  1c 80 95 8f              li      $s5, 0x400000
0x004009c0:  1c 80 97 8f              li      $s7, 0x400000
0x004009c4:  23 f0 53 00              subu    $fp, $v0, $s3
0x004009c8:  18 00 00 10              b       loc_400A2C
0x004009cc:  18 00 b6 27              addiu   $s6, $sp, 0xF020+var_F008
0x004009d0:  04 00 52 26              addiu   $s2, 4
0x004009d4:  00 00 44 8e              lw      $a0, 0($s2) # a1
0x004009d8:  00 00 00 00              nop
0x004009dc:  0e 00 80 10              beqz    $a0, loc_400A18
0x004009e0:  00 00 00 00              nop
0x004009e4:  5c 80 99 8f              la      $t9, nvram_get
0x004009e8:  00 00 00 00              nop
0x004009ec:  09 f8 20 03              jalr    $t9  # nvram_get
0x004009f0:  00 00 00 00              nop
0x004009f4:  18 00 a2 af              sw      $v0, 0xF020+var_F008($sp)
0x004009f8:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x004009fc:  06 00 40 10              beqz    $v0, loc_400A18
0x00400a00:  00 00 00 00              nop
0x00400a04:  78 80 99 8f              la      $t9, puts
0x00400a08:  00 00 00 00              nop
0x00400a0c:  09 f8 20 03              jalr    $t9  # puts
0x00400a10:  21 20 40 00              move    $a0, $v0 # s
0x00400a14:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400a18:  04 00 52 26              addiu   $s2, 4
0x00400a1c:  00 00 50 8e              lw      $s0, 0($s2)
0x00400a20:  00 00 00 00              nop
0x00400a24:  29 00 00 12              beqz    $s0, loc_400ACC
0x00400a28:  00 00 00 00              nop
0x00400a2c:  4c 80 99 8f              la      $t9, strcmp
0x00400a30:  21 20 00 02              move    $a0, $s0 # s1
0x00400a34:  c4 0e 85 26              addiu   $a1, $s4, (aGet - 0x400000) # "get"
0x00400a38:  09 f8 20 03              jalr    $t9  # strcmp
0x00400a3c:  21 88 20 03              move    $s1, $t9
0x00400a40:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400a44:  e2 ff 40 10              beqz    $v0, loc_4009D0
0x00400a48:  21 20 00 02              move    $a0, $s0 # s1
0x00400a4c:  4c 80 99 8f              la      $t9, strcmp
0x00400a50:  21 c8 20 02              move    $t9, $s1
0x00400a54:  09 f8 20 03              jalr    $t9  # strcmp
0x00400a58:  c8 0e a5 26              addiu   $a1, $s5, (aSet - 0x400000) # "set"
0x00400a5c:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400a60:  28 00 40 14              bnez    $v0, loc_400B04
0x00400a64:  21 20 00 02              move    $a0, $s0 # s1
0x00400a68:  04 00 52 26              addiu   $s2, 4
0x00400a6c:  00 00 45 8e              lw      $a1, 0($s2) # src
0x00400a70:  00 00 00 00              nop
0x00400a74:  e8 ff a0 10              beqz    $a1, loc_400A18
0x00400a78:  00 f0 06 34              li      $a2, 0xF000 # n
0x00400a7c:  64 80 99 8f              la      $t9, strncpy
0x00400a80:  21 20 60 02              move    $a0, $s3 # dest
0x00400a84:  09 f8 20 03              jalr    $t9  # strncpy
0x00400a88:  18 00 b3 af              sw      $s3, 0xF020+var_F008($sp)
0x00400a8c:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400a90:  21 20 c0 02              move    $a0, $s6 # stringp
0x00400a94:  40 80 99 8f              la      $t9, strsep
0x00400a98:  00 00 00 00              nop
0x00400a9c:  09 f8 20 03              jalr    $t9  # strsep
0x00400aa0:  cc 0e e5 26              addiu   $a1, $s7, (asc_400ECC - 0x400000) # "="
0x00400aa4:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400aa8:  18 00 a5 8f              lw      $a1, 0xF020+var_F008($sp) # a2
0x00400aac:  68 80 99 8f              la      $t9, nvram_set
0x00400ab0:  21 20 40 00              move    $a0, $v0 # a1
0x00400ab4:  09 f8 20 03              jalr    $t9  # nvram_set
0x00400ab8:  04 00 52 26              addiu   $s2, 4
0x00400abc:  00 00 50 8e              lw      $s0, 0($s2)
0x00400ac0:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400ac4:  d9 ff 00 16              bnez    $s0, loc_400A2C
0x00400ac8:  00 00 00 00              nop
0x00400acc:  58 70 bd 27              addiu   $sp, 0x7058
0x00400ad0:  ec 7f bf 8f              lw      $ra, 0x7FC8+var_s24($sp)
0x00400ad4:  e8 7f be 8f              lw      $fp, 0x7FC8+var_s20($sp)
0x00400ad8:  e4 7f b7 8f              lw      $s7, 0x7FC8+var_s1C($sp)
0x00400adc:  e0 7f b6 8f              lw      $s6, 0x7FC8+var_s18($sp)
0x00400ae0:  dc 7f b5 8f              lw      $s5, 0x7FC8+var_s14($sp)
0x00400ae4:  d8 7f b4 8f              lw      $s4, 0x7FC8+var_s10($sp)
0x00400ae8:  d4 7f b3 8f              lw      $s3, 0x7FC8+var_sC($sp)
0x00400aec:  d0 7f b2 8f              lw      $s2, 0x7FC8+var_s8($sp)
0x00400af0:  cc 7f b1 8f              lw      $s1, 0x7FC8+var_s4($sp)
0x00400af4:  c8 7f b0 8f              lw      $s0, 0x7FC8+var_s0($sp)
0x00400af8:  21 10 00 00              move    $v0, $zero
0x00400afc:  08 00 e0 03              jr      $ra
0x00400b00:  f0 7f bd 27              addiu   $sp, 0x7FF0
0x00400b04:  1c 80 82 8f              li      $v0, 0x400000
0x00400b08:  4c 80 99 8f              la      $t9, strcmp
0x00400b0c:  21 c8 20 02              move    $t9, $s1
0x00400b10:  09 f8 20 03              jalr    $t9  # strcmp
0x00400b14:  d0 0e 45 24              addiu   $a1, $v0, (aUnset - 0x400000) # "unset"
0x00400b18:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400b1c:  0d 00 40 14              bnez    $v0, loc_400B54
0x00400b20:  21 20 00 02              move    $a0, $s0 # s1
0x00400b24:  04 00 52 26              addiu   $s2, 4
0x00400b28:  00 00 44 8e              lw      $a0, 0($s2) # a1
0x00400b2c:  00 00 00 00              nop
0x00400b30:  b9 ff 80 10              beqz    $a0, loc_400A18
0x00400b34:  00 00 00 00              nop
0x00400b38:  54 80 99 8f              la      $t9, nvram_unset
0x00400b3c:  00 00 00 00              nop
0x00400b40:  09 f8 20 03              jalr    $t9  # nvram_unset
0x00400b44:  04 00 52 26              addiu   $s2, 4
0x00400b48:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400b4c:  b3 ff 00 10              b       loc_400A1C
0x00400b50:  00 00 00 00              nop
0x00400b54:  1c 80 82 8f              li      $v0, 0x400000
0x00400b58:  4c 80 99 8f              la      $t9, strcmp
0x00400b5c:  21 c8 20 02              move    $t9, $s1
0x00400b60:  09 f8 20 03              jalr    $t9  # strcmp
0x00400b64:  d8 0e 45 24              addiu   $a1, $v0, (aCommit - 0x400000) # "commit"
0x00400b68:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400b6c:  3c 00 40 10              beqz    $v0, loc_400C60
0x00400b70:  00 00 00 00              nop
0x00400b74:  1c 80 82 8f              li      $v0, 0x400000
0x00400b78:  4c 80 99 8f              la      $t9, strcmp
0x00400b7c:  21 20 00 02              move    $a0, $s0 # s1
0x00400b80:  21 c8 20 02              move    $t9, $s1
0x00400b84:  09 f8 20 03              jalr    $t9  # strcmp
0x00400b88:  e0 0e 45 24              addiu   $a1, $v0, (aShow - 0x400000) # "show"
0x00400b8c:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400b90:  09 00 40 10              beqz    $v0, loc_400BB8
0x00400b94:  21 20 00 02              move    $a0, $s0 # s1
0x00400b98:  1c 80 82 8f              li      $v0, 0x400000
0x00400b9c:  4c 80 99 8f              la      $t9, strcmp
0x00400ba0:  21 c8 20 02              move    $t9, $s1
0x00400ba4:  09 f8 20 03              jalr    $t9  # strcmp
0x00400ba8:  e8 0e 45 24              addiu   $a1, $v0, (aDump - 0x400000) # "dump"
0x00400bac:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400bb0:  3d 00 40 14              bnez    $v0, loc_400CA8
0x00400bb4:  00 00 00 00              nop
0x00400bb8:  84 80 99 8f              la      $t9, nvram_getall
0x00400bbc:  21 20 60 02              move    $a0, $s3 # a1
0x00400bc0:  09 f8 20 03              jalr    $t9  # nvram_getall
0x00400bc4:  00 f0 05 34              li      $a1, 0xF000 # a2
0x00400bc8:  1c 00 a3 83              lb      $v1, 0xF020+dest($sp)
0x00400bcc:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400bd0:  11 00 60 10              beqz    $v1, loc_400C18
0x00400bd4:  21 80 60 02              move    $s0, $s3
0x00400bd8:  78 80 99 8f              la      $t9, puts
0x00400bdc:  00 00 00 00              nop
0x00400be0:  09 f8 20 03              jalr    $t9  # puts
0x00400be4:  21 20 00 02              move    $a0, $s0 # s
0x00400be8:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400bec:  00 00 00 00              nop
0x00400bf0:  34 80 99 8f              la      $t9, strlen
0x00400bf4:  00 00 00 00              nop
0x00400bf8:  09 f8 20 03              jalr    $t9  # strlen
0x00400bfc:  21 20 00 02              move    $a0, $s0 # s
0x00400c00:  01 00 03 26              addiu   $v1, $s0, 1
0x00400c04:  21 80 62 00              addu    $s0, $v1, $v0
0x00400c08:  00 00 02 82              lb      $v0, 0($s0)
0x00400c0c:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400c10:  f1 ff 40 14              bnez    $v0, loc_400BD8
0x00400c14:  00 00 00 00              nop
0x00400c18:  00 00 42 8e              lw      $v0, 0($s2)
0x00400c1c:  64 00 03 24              li      $v1, 0x64  # 'd'
0x00400c20:  00 00 44 80              lb      $a0, 0($v0)
0x00400c24:  00 00 00 00              nop
0x00400c28:  7b ff 83 10              beq     $a0, $v1, loc_400A18
0x00400c2c:  21 30 d0 03              addu    $a2, $fp, $s0
0x00400c30:  44 80 82 8f              la      $v0, stderr
0x00400c34:  00 00 00 00              nop
0x00400c38:  00 00 44 8c              lw      $a0, (stderr - 0x441034)($v0) # stream
0x00400c3c:  1c 80 82 8f              li      $v0, 0x400000
0x00400c40:  6c 80 99 8f              la      $t9, fprintf
0x00400c44:  00 f0 07 34              li      $a3, 0xF000
0x00400c48:  23 38 e6 00              subu    $a3, $a2
0x00400c4c:  09 f8 20 03              jalr    $t9  # fprintf
0x00400c50:  f0 0e 45 24              addiu   $a1, $v0, (aSizeDBytesDLef - 0x400000) # "size: %d bytes (%d left)\n"
0x00400c54:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400c58:  70 ff 00 10              b       loc_400A1C
0x00400c5c:  04 00 52 26              addiu   $s2, 4
0x00400c60:  50 80 99 8f              la      $t9, nvram_commit
0x00400c64:  00 00 00 00              nop
0x00400c68:  09 f8 20 03              jalr    $t9  # nvram_commit
0x00400c6c:  04 00 52 26              addiu   $s2, 4
0x00400c70:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400c74:  69 ff 00 10              b       loc_400A1C
0x00400c78:  00 00 00 00              nop
0x00400c7c:  7c 80 99 8f              la      $t9, usage
0x00400c80:  00 00 00 00              nop
0x00400c84:  09 f8 20 03              jalr    $t9  # usage
0x00400c88:  00 00 00 00              nop
0x00400c8c:  04 00 30 8e              lw      $s0, 4($s1)
0x00400c90:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400c94:  8e ff 00 12              beqz    $s0, loc_400AD0
0x00400c98:  58 70 bd 27              addiu   $sp, 0x7058
0x00400c9c:  a8 8f bd 27              addiu   $sp, -0x7058
0x00400ca0:  44 ff 00 10              b       loc_4009B4
0x00400ca4:  1c 00 b3 27              addiu   $s3, $sp, 0xF020+dest
0x00400ca8:  7c 80 99 8f              la      $t9, usage
0x00400cac:  00 00 00 00              nop
0x00400cb0:  09 f8 20 03              jalr    $t9  # usage
0x00400cb4:  04 00 52 26              addiu   $s2, 4
0x00400cb8:  10 00 bc 8f              lw      $gp, 0xF020+var_F010($sp)
0x00400cbc:  57 ff 00 10              b       loc_400A1C
0x00400cc0:  00 00 00 00              nop
