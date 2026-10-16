; binary: ntpclient
; function: setup_receive
; symbol: setup_receive
; entry_ea: 0x4017c4
; source_sha256: bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2
; chunk: 0x4017c4-0x4019c4
0x004017c4:  05 00 1c 3c 7c c8 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x004017cc:  21 e0 99 03              addu    $gp, $t9
0x004017d0:  a8 ff bd 27              addiu   $sp, -0x58
0x004017d4:  50 00 bf af              sw      $ra, 0x48+var_s8($sp)
0x004017d8:  4c 00 b1 af              sw      $s1, 0x48+var_s4($sp)
0x004017dc:  48 00 b0 af              sw      $s0, 0x48+var_s0($sp)
0x004017e0:  10 00 bc af              sw      $gp, 0x48+var_38($sp)
0x004017e4:  21 88 80 00              move    $s1, $a0
0x004017e8:  00 84 06 00              sll     $s0, $a2, 16
0x004017ec:  03 84 10 00              sra     $s0, 16
0x004017f0:  18 00 a0 af              sw      $zero, 0x48+addr($sp)
0x004017f4:  1c 00 a0 af              sw      $zero, 0x48+addr.sa_data+2($sp)
0x004017f8:  20 00 a0 af              sw      $zero, 0x48+addr.sa_data+6($sp)
0x004017fc:  04 00 02 24              li      $v0, 4
0x00401800:  33 00 e2 14              bne     $a3, $v0, loc_4018D0
0x00401804:  24 00 a0 af              sw      $zero, 0x48+addr.sa_data+0xA($sp)
0x00401808:  02 00 02 24              li      $v0, 2
0x0040180c:  18 00 a2 a7              sh      $v0, 0x48+addr($sp)
0x00401810:  02 1a 05 00              srl     $v1, $a1, 8
0x00401814:  00 ff 63 30              andi    $v1, 0xFF00
0x00401818:  02 16 05 00              srl     $v0, $a1, 24
0x0040181c:  25 18 62 00              or      $v1, $v0
0x00401820:  00 ff a2 30              andi    $v0, $a1, 0xFF00
0x00401824:  00 12 02 00              sll     $v0, 8
0x00401828:  25 18 62 00              or      $v1, $v0
0x0040182c:  00 16 05 00              sll     $v0, $a1, 24
0x00401830:  25 18 62 00              or      $v1, $v0
0x00401834:  1c 00 a3 af              sw      $v1, 0x48+addr.sa_data+2($sp)
0x00401838:  ff ff 03 32              andi    $v1, $s0, 0xFFFF
0x0040183c:  ff 00 62 30              andi    $v0, $v1, 0xFF
0x00401840:  00 12 02 00              sll     $v0, 8
0x00401844:  02 1a 03 00              srl     $v1, 8
0x00401848:  25 10 43 00              or      $v0, $v1
0x0040184c:  1a 00 a2 a7              sh      $v0, 0x48+addr.sa_data($sp)
0x00401850:  18 00 a5 27              addiu   $a1, $sp, 0x48+addr # addr
0x00401854:  28 81 99 8f              la      $t9, bind
0x00401858:  00 00 00 00              nop
0x0040185c:  09 f8 20 03              jalr    $t9  # bind
0x00401860:  10 00 06 24              li      $a2, 0x10 # len
0x00401864:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x00401868:  ff ff 03 24              li      $v1, 0xFFFFFFFF
0x0040186c:  4a 00 43 14              bne     $v0, $v1, loc_401998
0x00401870:  00 00 00 00              nop
0x00401874:  90 80 82 8f              la      $v0, stderr
0x00401878:  00 00 00 00              nop
0x0040187c:  00 00 44 8c              lw      $a0, (stderr - 0x446E8C)($v0) # stream
0x00401880:  1c 80 85 8f              li      $a1, 0x400000
0x00401884:  00 00 00 00              nop
0x00401888:  4c 55 a5 24              addiu   $a1, (aCouldNotBindTo - 0x400000) # "could not bind to udp port %d\n"
0x0040188c:  2c 81 99 8f              la      $t9, fprintf
0x00401890:  00 00 00 00              nop
0x00401894:  09 f8 20 03              jalr    $t9  # fprintf
0x00401898:  21 30 00 02              move    $a2, $s0
0x0040189c:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x004018a0:  00 00 00 00              nop
0x004018a4:  1c 80 84 8f              li      $a0, 0x400000
0x004018a8:  64 81 99 8f              la      $t9, perror
0x004018ac:  00 00 00 00              nop
0x004018b0:  09 f8 20 03              jalr    $t9  # perror
0x004018b4:  6c 55 84 24              addiu   $a0, (aBind_0 - 0x400000) # "bind"
0x004018b8:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x004018bc:  00 00 00 00              nop
0x004018c0:  6c 80 99 8f              la      $t9, exit
0x004018c4:  00 00 00 00              nop
0x004018c8:  09 f8 20 03              jalr    $t9  # exit
0x004018cc:  01 00 04 24              li      $a0, 1 # status
0x004018d0:  0a 00 02 24              li      $v0, 0xA
0x004018d4:  28 00 a2 a7              sh      $v0, 0x48+var_20($sp)
0x004018d8:  0a 00 04 24              li      $a0, 0xA # af
0x004018dc:  1c 80 85 8f              li      $a1, 0x400000
0x004018e0:  00 00 00 00              nop
0x004018e4:  74 55 a5 24              addiu   $a1, (asc_405574 - 0x400000) # "::"
0x004018e8:  8c 81 99 8f              la      $t9, inet_pton
0x004018ec:  00 00 00 00              nop
0x004018f0:  09 f8 20 03              jalr    $t9  # inet_pton
0x004018f4:  30 00 a6 27              addiu   $a2, $sp, 0x48+var_20.sa_data+6 # buf
0x004018f8:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x004018fc:  ff ff 03 32              andi    $v1, $s0, 0xFFFF
0x00401900:  ff 00 62 30              andi    $v0, $v1, 0xFF
0x00401904:  00 12 02 00              sll     $v0, 8
0x00401908:  02 1a 03 00              srl     $v1, 8
0x0040190c:  25 10 43 00              or      $v0, $v1
0x00401910:  2a 00 a2 a7              sh      $v0, 0x48+var_20.sa_data($sp)
0x00401914:  21 20 20 02              move    $a0, $s1 # fd
0x00401918:  28 00 a5 27              addiu   $a1, $sp, 0x48+var_20 # addr
0x0040191c:  28 81 99 8f              la      $t9, bind
0x00401920:  00 00 00 00              nop
0x00401924:  09 f8 20 03              jalr    $t9  # bind
0x00401928:  1c 00 06 24              li      $a2, 0x1C # len
0x0040192c:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x00401930:  ff ff 03 24              li      $v1, 0xFFFFFFFF
0x00401934:  18 00 43 14              bne     $v0, $v1, loc_401998
0x00401938:  00 00 00 00              nop
0x0040193c:  90 80 82 8f              la      $v0, stderr
0x00401940:  00 00 00 00              nop
0x00401944:  00 00 44 8c              lw      $a0, (stderr - 0x446E8C)($v0) # stream
0x00401948:  1c 80 85 8f              li      $a1, 0x400000
0x0040194c:  00 00 00 00              nop
0x00401950:  4c 55 a5 24              addiu   $a1, (aCouldNotBindTo - 0x400000) # "could not bind to udp port %d\n"
0x00401954:  2c 81 99 8f              la      $t9, fprintf
0x00401958:  00 00 00 00              nop
0x0040195c:  09 f8 20 03              jalr    $t9  # fprintf
0x00401960:  21 30 00 02              move    $a2, $s0
0x00401964:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x00401968:  00 00 00 00              nop
0x0040196c:  1c 80 84 8f              li      $a0, 0x400000
0x00401970:  64 81 99 8f              la      $t9, perror
0x00401974:  00 00 00 00              nop
0x00401978:  09 f8 20 03              jalr    $t9  # perror
0x0040197c:  6c 55 84 24              addiu   $a0, (aBind_0 - 0x400000) # "bind"
0x00401980:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x00401984:  00 00 00 00              nop
0x00401988:  6c 80 99 8f              la      $t9, exit
0x0040198c:  00 00 00 00              nop
0x00401990:  09 f8 20 03              jalr    $t9  # exit
0x00401994:  01 00 04 24              li      $a0, 1 # status
0x00401998:  21 20 20 02              move    $a0, $s1 # fd
0x0040199c:  f8 80 99 8f              la      $t9, listen
0x004019a0:  00 00 00 00              nop
0x004019a4:  09 f8 20 03              jalr    $t9  # listen
0x004019a8:  03 00 05 24              li      $a1, 3 # n
0x004019ac:  10 00 bc 8f              lw      $gp, 0x48+var_38($sp)
0x004019b0:  50 00 bf 8f              lw      $ra, 0x48+var_s8($sp)
0x004019b4:  4c 00 b1 8f              lw      $s1, 0x48+var_s4($sp)
0x004019b8:  48 00 b0 8f              lw      $s0, 0x48+var_s0($sp)
0x004019bc:  08 00 e0 03              jr      $ra
0x004019c0:  58 00 bd 27              addiu   $sp, 0x58
