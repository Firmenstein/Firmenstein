; binary: libnvram.so
; function: sub_1B5C
; symbol: sub_1B5C
; entry_ea: 0x1b5c
; source_sha256: 6e90b0a95384f6ced071e1ee1d0aefcc3ccc0ef07074ccf142073d9d07de418f
; chunk: 0x1b5c-0x1d08
0x00001b5c:  05 00 1c 3c e4 9a 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x00001b64:  21 e0 99 03              addu    $gp, $t9
0x00001b68:  60 ff bd 27              addiu   $sp, -0xA0
0x00001b6c:  98 00 bf af              sw      $ra, 0x80+var_s18($sp)
0x00001b70:  94 00 b5 af              sw      $s5, 0x80+var_s14($sp)
0x00001b74:  90 00 b4 af              sw      $s4, 0x80+var_s10($sp)
0x00001b78:  8c 00 b3 af              sw      $s3, 0x80+var_sC($sp)
0x00001b7c:  88 00 b2 af              sw      $s2, 0x80+var_s8($sp)
0x00001b80:  84 00 b1 af              sw      $s1, 0x80+var_s4($sp)
0x00001b84:  80 00 b0 af              sw      $s0, 0x80+var_s0($sp)
0x00001b88:  10 00 bc af              sw      $gp, 0x80+var_70($sp)
0x00001b8c:  40 80 99 8f              la      $t9, strlen
0x00001b90:  21 98 a0 00              move    $s3, $a1
0x00001b94:  21 88 20 03              move    $s1, $t9
0x00001b98:  09 f8 20 03              jalr    $t9  # strlen
0x00001b9c:  21 a0 80 00              move    $s4, $a0
0x00001ba0:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x00001ba4:  21 20 00 00              move    $a0, $zero
0x00001ba8:  38 80 99 8f              la      $t9, nvram_init
0x00001bac:  00 00 00 00              nop
0x00001bb0:  09 f8 20 03              jalr    $t9  # nvram_init
0x00001bb4:  21 80 40 00              move    $s0, $v0
0x00001bb8:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x00001bbc:  2b 00 40 14              bnez    $v0, loc_1C6C
0x00001bc0:  00 00 00 00              nop
0x00001bc4:  08 00 60 12              beqz    $s3, loc_1BE8
0x00001bc8:  01 00 12 26              addiu   $s2, $s0, 1
0x00001bcc:  40 80 99 8f              la      $t9, strlen
0x00001bd0:  21 c8 20 02              move    $t9, $s1
0x00001bd4:  09 f8 20 03              jalr    $t9  # strlen
0x00001bd8:  21 20 60 02              move    $a0, $s3
0x00001bdc:  01 00 42 24              addiu   $v0, 1
0x00001be0:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x00001be4:  21 90 42 02              addu    $s2, $v0
0x00001be8:  65 00 42 2e              sltiu   $v0, $s2, 0x65  # 'e'
0x00001bec:  3b 00 40 10              beqz    $v0, loc_1CDC
0x00001bf0:  18 00 b1 27              addiu   $s1, $sp, 0x80+var_68
0x00001bf4:  21 a8 20 02              move    $s5, $s1
0x00001bf8:  31 00 60 12              beqz    $s3, loc_1CC0
0x00001bfc:  21 30 80 02              move    $a2, $s4
0x00001c00:  18 80 85 8f              li      $a1, 0
0x00001c04:  54 80 99 8f              la      $t9, sprintf
0x00001c08:  fc 28 a5 24              addiu   $a1, aSS # "%s=%s"
0x00001c0c:  21 38 60 02              move    $a3, $s3
0x00001c10:  09 f8 20 03              jalr    $t9  # sprintf
0x00001c14:  21 20 20 02              move    $a0, $s1
0x00001c18:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x00001c1c:  00 00 00 00              nop
0x00001c20:  1c 80 82 8f              li      $v0, 0x40000
0x00001c24:  88 80 99 8f              la      $t9, write
0x00001c28:  90 31 44 8c              lw      $a0, (_fdata - 0x40000)($v0)
0x00001c2c:  21 28 20 02              move    $a1, $s1
0x00001c30:  09 f8 20 03              jalr    $t9  # write
0x00001c34:  21 30 40 02              move    $a2, $s2
0x00001c38:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x00001c3c:  16 00 40 04              bltz    $v0, loc_1C98
0x00001c40:  21 80 40 00              move    $s0, $v0
0x00001c44:  06 00 b1 12              beq     $s5, $s1, loc_1C60
0x00001c48:  00 00 00 00              nop
0x00001c4c:  2c 80 99 8f              la      $t9, free
0x00001c50:  00 00 00 00              nop
0x00001c54:  09 f8 20 03              jalr    $t9  # free
0x00001c58:  21 20 20 02              move    $a0, $s1
0x00001c5c:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x00001c60:  0b 00 12 12              beq     $s0, $s2, loc_1C90
0x00001c64:  00 00 00 00              nop
0x00001c68:  21 10 00 02              move    $v0, $s0
0x00001c6c:  98 00 bf 8f              lw      $ra, 0x80+var_s18($sp)
0x00001c70:  94 00 b5 8f              lw      $s5, 0x80+var_s14($sp)
0x00001c74:  90 00 b4 8f              lw      $s4, 0x80+var_s10($sp)
0x00001c78:  8c 00 b3 8f              lw      $s3, 0x80+var_sC($sp)
0x00001c7c:  88 00 b2 8f              lw      $s2, 0x80+var_s8($sp)
0x00001c80:  84 00 b1 8f              lw      $s1, 0x80+var_s4($sp)
0x00001c84:  80 00 b0 8f              lw      $s0, 0x80+var_s0($sp)
0x00001c88:  08 00 e0 03              jr      $ra
0x00001c8c:  a0 00 bd 27              addiu   $sp, 0xA0
0x00001c90:  f5 ff 00 10              b       loc_1C68
0x00001c94:  21 80 00 00              move    $s0, $zero
0x00001c98:  18 80 84 8f              li      $a0, 0
0x00001c9c:  9c 80 99 8f              la      $t9, perror
0x00001ca0:  00 00 00 00              nop
0x00001ca4:  09 f8 20 03              jalr    $t9  # perror
0x00001ca8:  70 28 84 24              addiu   $a0, aDevNvram # "/dev/nvram"
0x00001cac:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x00001cb0:  e6 ff b1 16              bne     $s5, $s1, loc_1C4C
0x00001cb4:  00 00 00 00              nop
0x00001cb8:  e9 ff 00 10              b       loc_1C60
0x00001cbc:  00 00 00 00              nop
0x00001cc0:  ac 80 99 8f              la      $t9, strcpy
0x00001cc4:  21 28 80 02              move    $a1, $s4
0x00001cc8:  09 f8 20 03              jalr    $t9  # strcpy
0x00001ccc:  21 20 20 02              move    $a0, $s1
0x00001cd0:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x00001cd4:  d2 ff 00 10              b       loc_1C20
0x00001cd8:  00 00 00 00              nop
0x00001cdc:  94 80 99 8f              la      $t9, malloc
0x00001ce0:  00 00 00 00              nop
0x00001ce4:  09 f8 20 03              jalr    $t9  # malloc
0x00001ce8:  21 20 40 02              move    $a0, $s2
0x00001cec:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x00001cf0:  03 00 40 10              beqz    $v0, loc_1D00
0x00001cf4:  21 88 40 00              move    $s1, $v0
0x00001cf8:  bf ff 00 10              b       loc_1BF8
0x00001cfc:  18 00 b5 27              addiu   $s5, $sp, 0x80+var_68
0x00001d00:  da ff 00 10              b       loc_1C6C
0x00001d04:  f4 ff 02 24              li      $v0, 0xFFFFFFF4
