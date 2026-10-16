; binary: ntpclient
; function: setup_transmit
; symbol: setup_transmit
; entry_ea: 0x401b68
; source_sha256: bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2
; chunk: 0x401b68-0x401cf0
0x00401b68:  05 00 1c 3c d8 c4 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x00401b70:  21 e0 99 03              addu    $gp, $t9
0x00401b74:  a8 ff bd 27              addiu   $sp, -0x58
0x00401b78:  50 00 bf af              sw      $ra, 0x48+var_s8($sp)
0x00401b7c:  4c 00 b1 af              sw      $s1, 0x48+var_s4($sp)
0x00401b80:  48 00 b0 af              sw      $s0, 0x48+var_s0($sp)
0x00401b84:  10 00 bc af              sw      $gp, 0x48+var_38($sp)
0x00401b88:  21 88 80 00              move    $s1, $a0
0x00401b8c:  00 84 06 00              sll     $s0, $a2, 16
0x00401b90:  03 84 10 00              sra     $s0, 16
0x00401b94:  18 00 a0 af              sw      $zero, 0x48+addr($sp)
0x00401b98:  1c 00 a0 af              sw      $zero, 0x48+addr.sa_data+2($sp)
0x00401b9c:  20 00 a0 af              sw      $zero, 0x48+addr.sa_data+6($sp)
0x00401ba0:  24 00 a0 af              sw      $zero, 0x48+addr.sa_data+0xA($sp)
0x00401ba4:  28 00 a0 af              sw      $zero, 0x48+var_20($sp)
0x00401ba8:  2c 00 a0 af              sw      $zero, 0x48+var_20.sa_data+2($sp)
0x00401bac:  30 00 a0 af              sw      $zero, 0x48+var_20.sa_data+6($sp)
0x00401bb0:  34 00 a0 af              sw      $zero, 0x48+var_20.sa_data+0xA($sp)
0x00401bb4:  38 00 a0 af              sw      $zero, 0x48+var_10($sp)
0x00401bb8:  3c 00 a0 af              sw      $zero, 0x48+var_C($sp)
0x00401bbc:  04 00 02 24              li      $v0, 4
0x00401bc0:  23 00 e2 14              bne     $a3, $v0, loc_401C50
0x00401bc4:  40 00 a0 af              sw      $zero, 0x48+var_8($sp)
0x00401bc8:  02 00 02 24              li      $v0, 2
0x00401bcc:  18 00 a2 a7              sh      $v0, 0x48+addr($sp)
0x00401bd0:  1c 00 a4 27              addiu   $a0, $sp, 0x48+addr.sa_data+2
0x00401bd4:  80 81 99 8f              la      $t9, stuff_net_addr
0x00401bd8:  00 00 00 00              nop
0x00401bdc:  09 f8 20 03              jalr    $t9  # stuff_net_addr
0x00401be0:  04 00 06 24              li      $a2, 4
0x00401be4:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x00401be8:  3c 00 40 14              bnez    $v0, loc_401CDC
0x00401bec:  01 00 02 24              li      $v0, 1
0x00401bf0:  ff ff 03 32              andi    $v1, $s0, 0xFFFF
0x00401bf4:  ff 00 62 30              andi    $v0, $v1, 0xFF
0x00401bf8:  00 12 02 00              sll     $v0, 8
0x00401bfc:  02 1a 03 00              srl     $v1, 8
0x00401c00:  25 10 43 00              or      $v0, $v1
0x00401c04:  1a 00 a2 a7              sh      $v0, 0x48+addr.sa_data($sp)
0x00401c08:  21 20 20 02              move    $a0, $s1 # fd
0x00401c0c:  18 00 a5 27              addiu   $a1, $sp, 0x48+addr # addr
0x00401c10:  90 81 99 8f              la      $t9, connect
0x00401c14:  00 00 00 00              nop
0x00401c18:  09 f8 20 03              jalr    $t9  # connect
0x00401c1c:  10 00 06 24              li      $a2, 0x10 # len
0x00401c20:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x00401c24:  ff ff 03 24              li      $v1, 0xFFFFFFFF
0x00401c28:  2b 00 43 14              bne     $v0, $v1, loc_401CD8
0x00401c2c:  00 00 00 00              nop
0x00401c30:  1c 80 84 8f              li      $a0, 0x400000
0x00401c34:  64 81 99 8f              la      $t9, perror
0x00401c38:  00 00 00 00              nop
0x00401c3c:  09 f8 20 03              jalr    $t9  # perror
0x00401c40:  84 55 84 24              addiu   $a0, (aNtpclientConne - 0x400000) # "(ntpclient) connect"
0x00401c44:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x00401c48:  24 00 00 10              b       loc_401CDC
0x00401c4c:  01 00 02 24              li      $v0, 1
0x00401c50:  0a 00 02 24              li      $v0, 0xA
0x00401c54:  28 00 a2 a7              sh      $v0, 0x48+var_20($sp)
0x00401c58:  30 00 a4 27              addiu   $a0, $sp, 0x48+var_20.sa_data+6
0x00401c5c:  84 80 99 8f              la      $t9, stuff_net_addr6
0x00401c60:  00 00 00 00              nop
0x00401c64:  09 f8 20 03              jalr    $t9  # stuff_net_addr6
0x00401c68:  21 30 e0 00              move    $a2, $a3
0x00401c6c:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x00401c70:  1a 00 40 14              bnez    $v0, loc_401CDC
0x00401c74:  01 00 02 24              li      $v0, 1
0x00401c78:  ff ff 03 32              andi    $v1, $s0, 0xFFFF
0x00401c7c:  ff 00 62 30              andi    $v0, $v1, 0xFF
0x00401c80:  00 12 02 00              sll     $v0, 8
0x00401c84:  02 1a 03 00              srl     $v1, 8
0x00401c88:  25 10 43 00              or      $v0, $v1
0x00401c8c:  2a 00 a2 a7              sh      $v0, 0x48+var_20.sa_data($sp)
0x00401c90:  21 20 20 02              move    $a0, $s1 # fd
0x00401c94:  28 00 a5 27              addiu   $a1, $sp, 0x48+var_20 # addr
0x00401c98:  90 81 99 8f              la      $t9, connect
0x00401c9c:  00 00 00 00              nop
0x00401ca0:  09 f8 20 03              jalr    $t9  # connect
0x00401ca4:  1c 00 06 24              li      $a2, 0x1C # len
0x00401ca8:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x00401cac:  ff ff 03 24              li      $v1, 0xFFFFFFFF
0x00401cb0:  09 00 43 14              bne     $v0, $v1, loc_401CD8
0x00401cb4:  00 00 00 00              nop
0x00401cb8:  1c 80 84 8f              li      $a0, 0x400000
0x00401cbc:  64 81 99 8f              la      $t9, perror
0x00401cc0:  00 00 00 00              nop
0x00401cc4:  09 f8 20 03              jalr    $t9  # perror
0x00401cc8:  84 55 84 24              addiu   $a0, (aNtpclientConne - 0x400000) # "(ntpclient) connect"
0x00401ccc:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x00401cd0:  02 00 00 10              b       loc_401CDC
0x00401cd4:  01 00 02 24              li      $v0, 1
0x00401cd8:  21 10 00 00              move    $v0, $zero
0x00401cdc:  50 00 bf 8f              lw      $ra, 0x48+var_s8($sp)
0x00401ce0:  4c 00 b1 8f              lw      $s1, 0x48+var_s4($sp)
0x00401ce4:  48 00 b0 8f              lw      $s0, 0x48+var_s0($sp)
0x00401ce8:  08 00 e0 03              jr      $ra
0x00401cec:  58 00 bd 27              addiu   $sp, 0x58
