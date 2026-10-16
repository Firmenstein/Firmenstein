; binary: l2tp-control
; function: main
; symbol: main
; entry_ea: 0x400afc
; source_sha256: 63e9f422d199949f817437a16af5b6309f4e91629c2bdfd6b9f56d782e44e817
; chunk: 0x400afc-0x400d04
0x00400afc:  05 00 1c 3c 44 85 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x00400b04:  21 e0 99 03              addu    $gp, $t9
0x00400b08:  d0 ef bd 27              addiu   $sp, -0x1030
0x00400b0c:  2c 10 bf af              sw      $ra, 0x1028+var_s4($sp)
0x00400b10:  28 10 be af              sw      $fp, 0x1028+var_s0($sp)
0x00400b14:  21 f0 a0 03              move    $fp, $sp
0x00400b18:  10 00 bc af              sw      $gp, 0x1028+var_1018($sp)
0x00400b1c:  30 10 c4 af              sw      $a0, 0x1028+arg_0($fp)
0x00400b20:  34 10 c5 af              sw      $a1, 0x1028+arg_4($fp)
0x00400b24:  30 10 c3 8f              lw      $v1, 0x1028+arg_0($fp)
0x00400b28:  02 00 02 24              li      $v0, 2
0x00400b2c:  14 00 62 10              beq     $v1, $v0, loc_400B80
0x00400b30:  00 00 00 00              nop
0x00400b34:  40 80 82 8f              la      $v0, stderr
0x00400b38:  00 00 00 00              nop
0x00400b3c:  00 00 43 8c              lw      $v1, (stderr - 0x441120)($v0)
0x00400b40:  34 10 c2 8f              lw      $v0, 0x1028+arg_4($fp)
0x00400b44:  00 00 00 00              nop
0x00400b48:  00 00 46 8c              lw      $a2, 0($v0)
0x00400b4c:  21 20 60 00              move    $a0, $v1 # stream
0x00400b50:  1c 80 82 8f              li      $v0, 0x400000
0x00400b54:  00 00 00 00              nop
0x00400b58:  28 0f 45 24              addiu   $a1, $v0, (aUsageSCommand - 0x400000) # "Usage: %s command\n"
0x00400b5c:  5c 80 99 8f              la      $t9, fprintf
0x00400b60:  00 00 00 00              nop
0x00400b64:  09 f8 20 03              jalr    $t9  # fprintf
0x00400b68:  00 00 00 00              nop
0x00400b6c:  10 00 dc 8f              lw      $gp, 0x1028+var_1018($fp)
0x00400b70:  01 00 02 24              li      $v0, 1
0x00400b74:  20 10 c2 af              sw      $v0, 0x1028+var_8($fp)
0x00400b78:  5b 00 00 10              b       loc_400CE8
0x00400b7c:  00 00 00 00              nop
0x00400b80:  34 10 c2 8f              lw      $v0, 0x1028+arg_4($fp)
0x00400b84:  00 00 00 00              nop
0x00400b88:  04 00 42 24              addiu   $v0, 4
0x00400b8c:  00 00 42 8c              lw      $v0, 0($v0)
0x00400b90:  00 00 00 00              nop
0x00400b94:  21 20 40 00              move    $a0, $v0
0x00400b98:  1c 80 82 8f              li      $v0, 0x400000
0x00400b9c:  00 00 00 00              nop
0x00400ba0:  d0 08 59 24              addiu   $t9, $v0, (sub_4008D0 - 0x400000)
0x00400ba4:  09 f8 20 03              jalr    $t9  # sub_4008D0
0x00400ba8:  00 00 00 00              nop
0x00400bac:  10 00 dc 8f              lw      $gp, 0x1028+var_1018($fp)
0x00400bb0:  1c 00 c2 af              sw      $v0, 0x1028+fd($fp)
0x00400bb4:  1c 00 c2 8f              lw      $v0, 0x1028+fd($fp)
0x00400bb8:  00 00 00 00              nop
0x00400bbc:  05 00 41 04              bgez    $v0, loc_400BD4
0x00400bc0:  00 00 00 00              nop
0x00400bc4:  01 00 02 24              li      $v0, 1
0x00400bc8:  20 10 c2 af              sw      $v0, 0x1028+var_8($fp)
0x00400bcc:  46 00 00 10              b       loc_400CE8
0x00400bd0:  00 00 00 00              nop
0x00400bd4:  20 00 c2 27              addiu   $v0, $fp, 0x1028+buf
0x00400bd8:  1c 00 c4 8f              lw      $a0, 0x1028+fd($fp) # fd
0x00400bdc:  21 28 40 00              move    $a1, $v0 # buf
0x00400be0:  00 10 06 24              li      $a2, 0x1000 # nbytes
0x00400be4:  58 80 99 8f              la      $t9, read
0x00400be8:  00 00 00 00              nop
0x00400bec:  09 f8 20 03              jalr    $t9  # read
0x00400bf0:  00 00 00 00              nop
0x00400bf4:  10 00 dc 8f              lw      $gp, 0x1028+var_1018($fp)
0x00400bf8:  18 00 c2 af              sw      $v0, 0x1028+n($fp)
0x00400bfc:  18 00 c2 8f              lw      $v0, 0x1028+n($fp)
0x00400c00:  00 00 00 00              nop
0x00400c04:  19 00 41 04              bgez    $v0, loc_400C6C
0x00400c08:  00 00 00 00              nop
0x00400c0c:  1c 80 82 8f              li      $v0, 0x400000
0x00400c10:  00 00 00 00              nop
0x00400c14:  3c 0f 44 24              addiu   $a0, $v0, (aRead_0 - 0x400000) # "read"
0x00400c18:  70 80 99 8f              la      $t9, perror
0x00400c1c:  00 00 00 00              nop
0x00400c20:  09 f8 20 03              jalr    $t9  # perror
0x00400c24:  00 00 00 00              nop
0x00400c28:  10 00 dc 8f              lw      $gp, 0x1028+var_1018($fp)
0x00400c2c:  0a 00 04 24              li      $a0, 0xA # c
0x00400c30:  80 80 99 8f              la      $t9, putchar
0x00400c34:  00 00 00 00              nop
0x00400c38:  09 f8 20 03              jalr    $t9  # putchar
0x00400c3c:  00 00 00 00              nop
0x00400c40:  10 00 dc 8f              lw      $gp, 0x1028+var_1018($fp)
0x00400c44:  1c 00 c4 8f              lw      $a0, 0x1028+fd($fp) # fd
0x00400c48:  30 80 99 8f              la      $t9, close
0x00400c4c:  00 00 00 00              nop
0x00400c50:  09 f8 20 03              jalr    $t9  # close
0x00400c54:  00 00 00 00              nop
0x00400c58:  10 00 dc 8f              lw      $gp, 0x1028+var_1018($fp)
0x00400c5c:  01 00 02 24              li      $v0, 1
0x00400c60:  20 10 c2 af              sw      $v0, 0x1028+var_8($fp)
0x00400c64:  20 00 00 10              b       loc_400CE8
0x00400c68:  00 00 00 00              nop
0x00400c6c:  18 00 c2 8f              lw      $v0, 0x1028+n($fp)
0x00400c70:  00 00 00 00              nop
0x00400c74:  10 00 40 14              bnez    $v0, loc_400CB8
0x00400c78:  00 00 00 00              nop
0x00400c7c:  0a 00 04 24              li      $a0, 0xA # c
0x00400c80:  80 80 99 8f              la      $t9, putchar
0x00400c84:  00 00 00 00              nop
0x00400c88:  09 f8 20 03              jalr    $t9  # putchar
0x00400c8c:  00 00 00 00              nop
0x00400c90:  10 00 dc 8f              lw      $gp, 0x1028+var_1018($fp)
0x00400c94:  1c 00 c4 8f              lw      $a0, 0x1028+fd($fp) # fd
0x00400c98:  30 80 99 8f              la      $t9, close
0x00400c9c:  00 00 00 00              nop
0x00400ca0:  09 f8 20 03              jalr    $t9  # close
0x00400ca4:  00 00 00 00              nop
0x00400ca8:  10 00 dc 8f              lw      $gp, 0x1028+var_1018($fp)
0x00400cac:  20 10 c0 af              sw      $zero, 0x1028+var_8($fp)
0x00400cb0:  0d 00 00 10              b       loc_400CE8
0x00400cb4:  00 00 00 00              nop
0x00400cb8:  18 00 c3 8f              lw      $v1, 0x1028+n($fp)
0x00400cbc:  20 00 c2 27              addiu   $v0, $fp, 0x1028+buf
0x00400cc0:  01 00 04 24              li      $a0, 1 # fd
0x00400cc4:  21 28 40 00              move    $a1, $v0 # buf
0x00400cc8:  21 30 60 00              move    $a2, $v1 # n
0x00400ccc:  60 80 99 8f              la      $t9, write
0x00400cd0:  00 00 00 00              nop
0x00400cd4:  09 f8 20 03              jalr    $t9  # write
0x00400cd8:  00 00 00 00              nop
0x00400cdc:  10 00 dc 8f              lw      $gp, 0x1028+var_1018($fp)
0x00400ce0:  bc ff 00 10              b       loc_400BD4
0x00400ce4:  00 00 00 00              nop
0x00400ce8:  20 10 c2 8f              lw      $v0, 0x1028+var_8($fp)
0x00400cec:  21 e8 c0 03              move    $sp, $fp
0x00400cf0:  2c 10 bf 8f              lw      $ra, 0x1028+var_s4($sp)
0x00400cf4:  28 10 be 8f              lw      $fp, 0x1028+var_s0($sp)
0x00400cf8:  30 10 bd 27              addiu   $sp, 0x1030
0x00400cfc:  08 00 e0 03              jr      $ra
0x00400d00:  00 00 00 00              nop
