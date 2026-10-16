; binary: libnvram.so
; function: nvram_commit
; symbol: nvram_commit
; entry_ea: 0x17f4
; source_sha256: 6e90b0a95384f6ced071e1ee1d0aefcc3ccc0ef07074ccf142073d9d07de418f
; chunk: 0x17f4-0x1b5c
0x000017f4:  05 00 1c 3c 4c 9e 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x000017fc:  21 e0 99 03              addu    $gp, $t9
0x00001800:  d0 ff bd 27              addiu   $sp, -0x30
0x00001804:  2c 00 bf af              sw      $ra, 0x18+var_s14($sp)
0x00001808:  28 00 b4 af              sw      $s4, 0x18+var_s10($sp)
0x0000180c:  24 00 b3 af              sw      $s3, 0x18+var_sC($sp)
0x00001810:  20 00 b2 af              sw      $s2, 0x18+var_s8($sp)
0x00001814:  1c 00 b1 af              sw      $s1, 0x18+var_s4($sp)
0x00001818:  18 00 b0 af              sw      $s0, 0x18+var_s0($sp)
0x0000181c:  10 00 bc af              sw      $gp, 0x18+var_8($sp)
0x00001820:  18 80 93 8f              li      $s3, 0
0x00001824:  18 80 94 8f              li      $s4, 0
0x00001828:  6c 80 99 8f              la      $t9, fopen
0x0000182c:  04 27 64 26              addiu   $a0, $s3, aDevConsole # "/dev/console"
0x00001830:  e0 26 85 26              addiu   $a1, $s4, unk_26E0
0x00001834:  09 f8 20 03              jalr    $t9  # fopen
0x00001838:  21 80 20 03              move    $s0, $t9
0x0000183c:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001840:  14 00 40 10              beqz    $v0, loc_1894
0x00001844:  21 88 40 00              move    $s1, $v0
0x00001848:  a4 80 99 8f              la      $t9, getpid
0x0000184c:  00 00 00 00              nop
0x00001850:  09 f8 20 03              jalr    $t9  # getpid
0x00001854:  00 00 00 00              nop
0x00001858:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x0000185c:  21 20 20 02              move    $a0, $s1
0x00001860:  18 80 85 8f              li      $a1, 0
0x00001864:  84 80 99 8f              la      $t9, fprintf
0x00001868:  7c 28 a5 24              addiu   $a1, aDNvramCommitSt # "%d nvram_commit(): start\n"
0x0000186c:  09 f8 20 03              jalr    $t9  # fprintf
0x00001870:  21 30 40 00              move    $a2, $v0
0x00001874:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001878:  00 00 00 00              nop
0x0000187c:  60 80 99 8f              la      $t9, fclose
0x00001880:  00 00 00 00              nop
0x00001884:  09 f8 20 03              jalr    $t9  # fclose
0x00001888:  21 20 20 02              move    $a0, $s1
0x0000188c:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001890:  00 00 00 00              nop
0x00001894:  50 80 99 8f              la      $t9, check_action
0x00001898:  00 00 00 00              nop
0x0000189c:  09 f8 20 03              jalr    $t9  # check_action
0x000018a0:  00 00 00 00              nop
0x000018a4:  06 00 03 24              li      $v1, 6
0x000018a8:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x000018ac:  7e 00 43 10              beq     $v0, $v1, loc_1AA8
0x000018b0:  04 27 64 26              addiu   $a0, $s3, aDevConsole # "/dev/console"
0x000018b4:  50 80 99 8f              la      $t9, check_action
0x000018b8:  00 00 00 00              nop
0x000018bc:  09 f8 20 03              jalr    $t9  # check_action
0x000018c0:  21 88 20 03              move    $s1, $t9
0x000018c4:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x000018c8:  2a 00 40 10              beqz    $v0, loc_1974
0x000018cc:  00 00 00 00              nop
0x000018d0:  50 80 99 8f              la      $t9, check_action
0x000018d4:  21 c8 20 02              move    $t9, $s1
0x000018d8:  09 f8 20 03              jalr    $t9  # check_action
0x000018dc:  00 00 00 00              nop
0x000018e0:  04 00 03 24              li      $v1, 4
0x000018e4:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x000018e8:  22 00 43 10              beq     $v0, $v1, loc_1974
0x000018ec:  00 00 00 00              nop
0x000018f0:  50 80 99 8f              la      $t9, check_action
0x000018f4:  21 c8 20 02              move    $t9, $s1
0x000018f8:  09 f8 20 03              jalr    $t9  # check_action
0x000018fc:  00 00 00 00              nop
0x00001900:  05 00 03 24              li      $v1, 5
0x00001904:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001908:  1a 00 43 10              beq     $v0, $v1, loc_1974
0x0000190c:  00 00 00 00              nop
0x00001910:  50 80 99 8f              la      $t9, check_action
0x00001914:  21 c8 20 02              move    $t9, $s1
0x00001918:  09 f8 20 03              jalr    $t9  # check_action
0x0000191c:  00 00 00 00              nop
0x00001920:  07 00 03 24              li      $v1, 7
0x00001924:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001928:  12 00 43 10              beq     $v0, $v1, loc_1974
0x0000192c:  00 00 00 00              nop
0x00001930:  6c 80 99 8f              la      $t9, fopen
0x00001934:  04 27 64 26              addiu   $a0, $s3, aDevConsole # "/dev/console"
0x00001938:  09 f8 20 03              jalr    $t9  # fopen
0x0000193c:  e0 26 85 26              addiu   $a1, $s4, unk_26E0
0x00001940:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001944:  7b 00 40 10              beqz    $v0, loc_1B34
0x00001948:  21 88 40 00              move    $s1, $v0
0x0000194c:  a4 80 99 8f              la      $t9, getpid
0x00001950:  00 00 00 00              nop
0x00001954:  09 f8 20 03              jalr    $t9  # getpid
0x00001958:  21 80 00 00              move    $s0, $zero
0x0000195c:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001960:  21 20 20 02              move    $a0, $s1
0x00001964:  18 80 85 8f              li      $a1, 0
0x00001968:  84 80 99 8f              la      $t9, fprintf
0x0000196c:  3c 00 00 10              b       loc_1A60
0x00001970:  d4 28 a5 24              addiu   $a1, aDNvramCommitNo # "%d nvram_commit():  nothing to do...\n"
0x00001974:  18 80 92 8f              li      $s2, 0
0x00001978:  18 80 85 8f              li      $a1, 0
0x0000197c:  44 80 99 8f              la      $t9, buf_to_file
0x00001980:  18 28 a5 24              addiu   $a1, aActNvramCommit # "ACT_NVRAM_COMMIT"
0x00001984:  e4 26 44 26              addiu   $a0, $s2, aTmpAction # "/tmp/action"
0x00001988:  09 f8 20 03              jalr    $t9  # buf_to_file
0x0000198c:  21 88 20 03              move    $s1, $t9
0x00001990:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001994:  00 00 00 00              nop
0x00001998:  38 80 99 8f              la      $t9, nvram_init
0x0000199c:  00 00 00 00              nop
0x000019a0:  09 f8 20 03              jalr    $t9  # nvram_init
0x000019a4:  21 20 00 00              move    $a0, $zero
0x000019a8:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x000019ac:  0a 00 40 10              beqz    $v0, loc_19D8
0x000019b0:  21 80 40 00              move    $s0, $v0
0x000019b4:  21 10 00 02              move    $v0, $s0
0x000019b8:  2c 00 bf 8f              lw      $ra, 0x18+var_s14($sp)
0x000019bc:  28 00 b4 8f              lw      $s4, 0x18+var_s10($sp)
0x000019c0:  24 00 b3 8f              lw      $s3, 0x18+var_sC($sp)
0x000019c4:  20 00 b2 8f              lw      $s2, 0x18+var_s8($sp)
0x000019c8:  1c 00 b1 8f              lw      $s1, 0x18+var_s4($sp)
0x000019cc:  18 00 b0 8f              lw      $s0, 0x18+var_s0($sp)
0x000019d0:  08 00 e0 03              jr      $ra
0x000019d4:  30 00 bd 27              addiu   $sp, 0x30
0x000019d8:  1c 80 82 8f              li      $v0, 0x40000
0x000019dc:  a8 80 99 8f              la      $t9, ioctl
0x000019e0:  90 31 44 8c              lw      $a0, (_fdata - 0x40000)($v0)
0x000019e4:  53 48 05 3c 46 4c a5 34  li      $a1, 0x48534C46
0x000019ec:  09 f8 20 03              jalr    $t9  # ioctl
0x000019f0:  21 30 00 00              move    $a2, $zero
0x000019f4:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x000019f8:  50 00 40 04              bltz    $v0, loc_1B3C
0x000019fc:  21 80 40 00              move    $s0, $v0
0x00001a00:  18 80 85 8f              li      $a1, 0
0x00001a04:  44 80 99 8f              la      $t9, buf_to_file
0x00001a08:  e4 26 44 26              addiu   $a0, $s2, aTmpAction # "/tmp/action"
0x00001a0c:  21 c8 20 02              move    $t9, $s1
0x00001a10:  09 f8 20 03              jalr    $t9  # buf_to_file
0x00001a14:  b0 28 a5 24              addiu   $a1, aActIdle # "ACT_IDLE"
0x00001a18:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001a1c:  04 27 64 26              addiu   $a0, $s3, aDevConsole # "/dev/console"
0x00001a20:  6c 80 99 8f              la      $t9, fopen
0x00001a24:  00 00 00 00              nop
0x00001a28:  09 f8 20 03              jalr    $t9  # fopen
0x00001a2c:  e0 26 85 26              addiu   $a1, $s4, unk_26E0
0x00001a30:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001a34:  df ff 40 10              beqz    $v0, loc_19B4
0x00001a38:  21 88 40 00              move    $s1, $v0
0x00001a3c:  a4 80 99 8f              la      $t9, getpid
0x00001a40:  00 00 00 00              nop
0x00001a44:  09 f8 20 03              jalr    $t9  # getpid
0x00001a48:  00 00 00 00              nop
0x00001a4c:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001a50:  21 20 20 02              move    $a0, $s1
0x00001a54:  18 80 85 8f              li      $a1, 0
0x00001a58:  84 80 99 8f              la      $t9, fprintf
0x00001a5c:  bc 28 a5 24              addiu   $a1, aDNvramCommitEn # "%d nvram_commit(): end\n"
0x00001a60:  09 f8 20 03              jalr    $t9  # fprintf
0x00001a64:  21 30 40 00              move    $a2, $v0
0x00001a68:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001a6c:  00 00 00 00              nop
0x00001a70:  60 80 99 8f              la      $t9, fclose
0x00001a74:  00 00 00 00              nop
0x00001a78:  09 f8 20 03              jalr    $t9  # fclose
0x00001a7c:  21 20 20 02              move    $a0, $s1
0x00001a80:  21 10 00 02              move    $v0, $s0
0x00001a84:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001a88:  2c 00 bf 8f              lw      $ra, 0x18+var_s14($sp)
0x00001a8c:  28 00 b4 8f              lw      $s4, 0x18+var_s10($sp)
0x00001a90:  24 00 b3 8f              lw      $s3, 0x18+var_sC($sp)
0x00001a94:  20 00 b2 8f              lw      $s2, 0x18+var_s8($sp)
0x00001a98:  1c 00 b1 8f              lw      $s1, 0x18+var_s4($sp)
0x00001a9c:  18 00 b0 8f              lw      $s0, 0x18+var_s0($sp)
0x00001aa0:  08 00 e0 03              jr      $ra
0x00001aa4:  30 00 bd 27              addiu   $sp, 0x30
0x00001aa8:  6c 80 99 8f              la      $t9, fopen
0x00001aac:  21 c8 00 02              move    $t9, $s0
0x00001ab0:  09 f8 20 03              jalr    $t9  # fopen
0x00001ab4:  e0 26 85 26              addiu   $a1, $s4, unk_26E0
0x00001ab8:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001abc:  10 00 40 10              beqz    $v0, loc_1B00
0x00001ac0:  21 80 40 00              move    $s0, $v0
0x00001ac4:  18 80 84 8f              li      $a0, 0
0x00001ac8:  4c 80 99 8f              la      $t9, fwrite
0x00001acc:  98 28 84 24              addiu   $a0, aWaiting2Second # "Waiting 2 seconds...\n"
0x00001ad0:  01 00 05 24              li      $a1, 1
0x00001ad4:  15 00 06 24              li      $a2, 0x15
0x00001ad8:  09 f8 20 03              jalr    $t9  # fwrite
0x00001adc:  21 38 40 00              move    $a3, $v0
0x00001ae0:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001ae4:  00 00 00 00              nop
0x00001ae8:  60 80 99 8f              la      $t9, fclose
0x00001aec:  00 00 00 00              nop
0x00001af0:  09 f8 20 03              jalr    $t9  # fclose
0x00001af4:  21 20 00 02              move    $a0, $s0
0x00001af8:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001afc:  00 00 00 00              nop
0x00001b00:  90 80 99 8f              la      $t9, sleep
0x00001b04:  01 00 04 24              li      $a0, 1
0x00001b08:  09 f8 20 03              jalr    $t9  # sleep
0x00001b0c:  21 88 20 03              move    $s1, $t9
0x00001b10:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001b14:  00 00 00 00              nop
0x00001b18:  90 80 99 8f              la      $t9, sleep
0x00001b1c:  21 c8 20 02              move    $t9, $s1
0x00001b20:  09 f8 20 03              jalr    $t9  # sleep
0x00001b24:  01 00 04 24              li      $a0, 1
0x00001b28:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001b2c:  61 ff 00 10              b       loc_18B4
0x00001b30:  00 00 00 00              nop
0x00001b34:  9f ff 00 10              b       loc_19B4
0x00001b38:  21 80 00 00              move    $s0, $zero
0x00001b3c:  18 80 84 8f              li      $a0, 0
0x00001b40:  9c 80 99 8f              la      $t9, perror
0x00001b44:  00 00 00 00              nop
0x00001b48:  09 f8 20 03              jalr    $t9  # perror
0x00001b4c:  70 28 84 24              addiu   $a0, aDevNvram # "/dev/nvram"
0x00001b50:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001b54:  aa ff 00 10              b       loc_1A00
0x00001b58:  00 00 00 00              nop
