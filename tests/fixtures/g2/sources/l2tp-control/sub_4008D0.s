; binary: l2tp-control
; function: sub_4008D0
; symbol: sub_4008D0
; entry_ea: 0x4008d0
; source_sha256: 63e9f422d199949f817437a16af5b6309f4e91629c2bdfd6b9f56d782e44e817
; chunk: 0x4008d0-0x400afc
0x004008d0:  05 00 1c 3c 70 87 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x004008d8:  21 e0 99 03              addu    $gp, $t9
0x004008dc:  50 ff bd 27              addiu   $sp, -0xB0
0x004008e0:  ac 00 bf af              sw      $ra, 0xA8+var_s4($sp)
0x004008e4:  a8 00 be af              sw      $fp, 0xA8+var_s0($sp)
0x004008e8:  21 f0 a0 03              move    $fp, $sp
0x004008ec:  10 00 bc af              sw      $gp, 0xA8+var_98($sp)
0x004008f0:  b0 00 c4 af              sw      $a0, 0xA8+arg_0($fp)
0x004008f4:  b0 00 c2 8f              lw      $v0, 0xA8+arg_0($fp)
0x004008f8:  00 00 00 00              nop
0x004008fc:  00 00 42 80              lb      $v0, 0($v0)
0x00400900:  00 00 00 00              nop
0x00400904:  0d 00 40 14              bnez    $v0, loc_40093C
0x00400908:  00 00 00 00              nop
0x0040090c:  3c 80 99 8f              la      $t9, __errno_location
0x00400910:  00 00 00 00              nop
0x00400914:  09 f8 20 03              jalr    $t9  # __errno_location
0x00400918:  00 00 00 00              nop
0x0040091c:  10 00 dc 8f              lw      $gp, 0xA8+var_98($fp)
0x00400920:  21 18 40 00              move    $v1, $v0
0x00400924:  1d 00 02 24              li      $v0, 0x1D
0x00400928:  00 00 62 ac              sw      $v0, 0($v1)
0x0040092c:  ff ff 02 24              li      $v0, 0xFFFFFFFF
0x00400930:  a0 00 c2 af              sw      $v0, 0xA8+var_8($fp)
0x00400934:  6a 00 00 10              b       loc_400AE0
0x00400938:  00 00 00 00              nop
0x0040093c:  1c 00 c2 27              addiu   $v0, $fp, 0xA8+s
0x00400940:  21 20 40 00              move    $a0, $v0 # s
0x00400944:  21 28 00 00              move    $a1, $zero # c
0x00400948:  6e 00 06 24              li      $a2, 0x6E  # 'n' # n
0x0040094c:  4c 80 99 8f              la      $t9, memset
0x00400950:  00 00 00 00              nop
0x00400954:  09 f8 20 03              jalr    $t9  # memset
0x00400958:  00 00 00 00              nop
0x0040095c:  10 00 dc 8f              lw      $gp, 0xA8+var_98($fp)
0x00400960:  01 00 02 24              li      $v0, 1
0x00400964:  1c 00 c2 a7              sh      $v0, 0xA8+s($fp)
0x00400968:  1c 00 c2 27              addiu   $v0, $fp, 0xA8+s
0x0040096c:  02 00 42 24              addiu   $v0, 2
0x00400970:  21 20 40 00              move    $a0, $v0 # dest
0x00400974:  1c 80 82 8f              li      $v0, 0x400000
0x00400978:  00 00 00 00              nop
0x0040097c:  00 0f 45 24              addiu   $a1, $v0, (aVarRunL2tpctrl - 0x400000) # "/var/run/l2tpctrl"
0x00400980:  6b 00 06 24              li      $a2, 0x6B  # 'k' # n
0x00400984:  54 80 99 8f              la      $t9, strncpy
0x00400988:  00 00 00 00              nop
0x0040098c:  09 f8 20 03              jalr    $t9  # strncpy
0x00400990:  00 00 00 00              nop
0x00400994:  10 00 dc 8f              lw      $gp, 0xA8+var_98($fp)
0x00400998:  01 00 04 24              li      $a0, 1 # domain
0x0040099c:  02 00 05 24              li      $a1, 2 # type
0x004009a0:  21 30 00 00              move    $a2, $zero # protocol
0x004009a4:  6c 80 99 8f              la      $t9, socket
0x004009a8:  00 00 00 00              nop
0x004009ac:  09 f8 20 03              jalr    $t9  # socket
0x004009b0:  00 00 00 00              nop
0x004009b4:  10 00 dc 8f              lw      $gp, 0xA8+var_98($fp)
0x004009b8:  18 00 c2 af              sw      $v0, 0xA8+fd($fp)
0x004009bc:  18 00 c2 8f              lw      $v0, 0xA8+fd($fp)
0x004009c0:  00 00 00 00              nop
0x004009c4:  0d 00 41 04              bgez    $v0, loc_4009FC
0x004009c8:  00 00 00 00              nop
0x004009cc:  1c 80 82 8f              li      $v0, 0x400000
0x004009d0:  00 00 00 00              nop
0x004009d4:  14 0f 44 24              addiu   $a0, $v0, (aSocket_0 - 0x400000) # "socket"
0x004009d8:  70 80 99 8f              la      $t9, perror
0x004009dc:  00 00 00 00              nop
0x004009e0:  09 f8 20 03              jalr    $t9  # perror
0x004009e4:  00 00 00 00              nop
0x004009e8:  10 00 dc 8f              lw      $gp, 0xA8+var_98($fp)
0x004009ec:  ff ff 02 24              li      $v0, 0xFFFFFFFF
0x004009f0:  a0 00 c2 af              sw      $v0, 0xA8+var_8($fp)
0x004009f4:  3a 00 00 10              b       loc_400AE0
0x004009f8:  00 00 00 00              nop
0x004009fc:  1c 00 c2 27              addiu   $v0, $fp, 0xA8+s
0x00400a00:  18 00 c4 8f              lw      $a0, 0xA8+fd($fp) # fd
0x00400a04:  21 28 40 00              move    $a1, $v0 # addr
0x00400a08:  6e 00 06 24              li      $a2, 0x6E  # 'n' # len
0x00400a0c:  78 80 99 8f              la      $t9, connect
0x00400a10:  00 00 00 00              nop
0x00400a14:  09 f8 20 03              jalr    $t9  # connect
0x00400a18:  00 00 00 00              nop
0x00400a1c:  10 00 dc 8f              lw      $gp, 0xA8+var_98($fp)
0x00400a20:  13 00 41 04              bgez    $v0, loc_400A70
0x00400a24:  00 00 00 00              nop
0x00400a28:  1c 80 82 8f              li      $v0, 0x400000
0x00400a2c:  00 00 00 00              nop
0x00400a30:  1c 0f 44 24              addiu   $a0, $v0, (aConnect_0 - 0x400000) # "connect"
0x00400a34:  70 80 99 8f              la      $t9, perror
0x00400a38:  00 00 00 00              nop
0x00400a3c:  09 f8 20 03              jalr    $t9  # perror
0x00400a40:  00 00 00 00              nop
0x00400a44:  10 00 dc 8f              lw      $gp, 0xA8+var_98($fp)
0x00400a48:  18 00 c4 8f              lw      $a0, 0xA8+fd($fp) # fd
0x00400a4c:  30 80 99 8f              la      $t9, close
0x00400a50:  00 00 00 00              nop
0x00400a54:  09 f8 20 03              jalr    $t9  # close
0x00400a58:  00 00 00 00              nop
0x00400a5c:  10 00 dc 8f              lw      $gp, 0xA8+var_98($fp)
0x00400a60:  ff ff 02 24              li      $v0, 0xFFFFFFFF
0x00400a64:  a0 00 c2 af              sw      $v0, 0xA8+var_8($fp)
0x00400a68:  1d 00 00 10              b       loc_400AE0
0x00400a6c:  00 00 00 00              nop
0x00400a70:  b0 00 c2 8f              lw      $v0, 0xA8+arg_0($fp)
0x00400a74:  00 00 00 00              nop
0x00400a78:  8c 00 c2 af              sw      $v0, 0xA8+iovec($fp)
0x00400a7c:  b0 00 c4 8f              lw      $a0, 0xA8+arg_0($fp) # s
0x00400a80:  38 80 99 8f              la      $t9, strlen
0x00400a84:  00 00 00 00              nop
0x00400a88:  09 f8 20 03              jalr    $t9  # strlen
0x00400a8c:  00 00 00 00              nop
0x00400a90:  10 00 dc 8f              lw      $gp, 0xA8+var_98($fp)
0x00400a94:  90 00 c2 af              sw      $v0, 0xA8+iovec.iov_len($fp)
0x00400a98:  1c 80 82 8f              li      $v0, 0x400000
0x00400a9c:  00 00 00 00              nop
0x00400aa0:  24 0f 42 24              addiu   $v0, (asc_400F24 - 0x400000) # "\n"
0x00400aa4:  94 00 c2 af              sw      $v0, 0xA8+var_14($fp)
0x00400aa8:  01 00 02 24              li      $v0, 1
0x00400aac:  98 00 c2 af              sw      $v0, 0xA8+var_10($fp)
0x00400ab0:  8c 00 c2 27              addiu   $v0, $fp, 0xA8+iovec
0x00400ab4:  18 00 c4 8f              lw      $a0, 0xA8+fd($fp) # fd
0x00400ab8:  21 28 40 00              move    $a1, $v0 # iovec
0x00400abc:  02 00 06 24              li      $a2, 2 # count
0x00400ac0:  7c 80 99 8f              la      $t9, writev
0x00400ac4:  00 00 00 00              nop
0x00400ac8:  09 f8 20 03              jalr    $t9  # writev
0x00400acc:  00 00 00 00              nop
0x00400ad0:  10 00 dc 8f              lw      $gp, 0xA8+var_98($fp)
0x00400ad4:  18 00 c2 8f              lw      $v0, 0xA8+fd($fp)
0x00400ad8:  00 00 00 00              nop
0x00400adc:  a0 00 c2 af              sw      $v0, 0xA8+var_8($fp)
0x00400ae0:  a0 00 c2 8f              lw      $v0, 0xA8+var_8($fp)
0x00400ae4:  21 e8 c0 03              move    $sp, $fp
0x00400ae8:  ac 00 bf 8f              lw      $ra, 0xA8+var_s4($sp)
0x00400aec:  a8 00 be 8f              lw      $fp, 0xA8+var_s0($sp)
0x00400af0:  b0 00 bd 27              addiu   $sp, 0xB0
0x00400af4:  08 00 e0 03              jr      $ra
0x00400af8:  00 00 00 00              nop
