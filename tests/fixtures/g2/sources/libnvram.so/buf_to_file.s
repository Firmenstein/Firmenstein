; binary: libnvram.so
; function: buf_to_file
; symbol: buf_to_file
; entry_ea: 0x1130
; source_sha256: 6e90b0a95384f6ced071e1ee1d0aefcc3ccc0ef07074ccf142073d9d07de418f
; chunk: 0x1130-0x11d0
0x00001130:  05 00 1c 3c 10 a5 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x00001138:  21 e0 99 03              addu    $gp, $t9
0x0000113c:  d8 ff bd 27              addiu   $sp, -0x28
0x00001140:  20 00 bf af              sw      $ra, 0x18+var_s8($sp)
0x00001144:  1c 00 b1 af              sw      $s1, 0x18+var_s4($sp)
0x00001148:  18 00 b0 af              sw      $s0, 0x18+var_s0($sp)
0x0000114c:  10 00 bc af              sw      $gp, 0x18+var_8($sp)
0x00001150:  21 88 a0 00              move    $s1, $a1
0x00001154:  18 80 85 8f              li      $a1, 0
0x00001158:  6c 80 99 8f              la      $t9, fopen
0x0000115c:  00 00 00 00              nop
0x00001160:  09 f8 20 03              jalr    $t9  # fopen
0x00001164:  e0 26 a5 24              addiu   $a1, unk_26E0
0x00001168:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x0000116c:  12 00 40 10              beqz    $v0, loc_11B8
0x00001170:  21 80 40 00              move    $s0, $v0
0x00001174:  34 80 99 8f              la      $t9, fputs
0x00001178:  21 20 20 02              move    $a0, $s1
0x0000117c:  09 f8 20 03              jalr    $t9  # fputs
0x00001180:  21 28 40 00              move    $a1, $v0
0x00001184:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x00001188:  00 00 00 00              nop
0x0000118c:  60 80 99 8f              la      $t9, fclose
0x00001190:  00 00 00 00              nop
0x00001194:  09 f8 20 03              jalr    $t9  # fclose
0x00001198:  21 20 00 02              move    $a0, $s0
0x0000119c:  10 00 bc 8f              lw      $gp, 0x18+var_8($sp)
0x000011a0:  20 00 bf 8f              lw      $ra, 0x18+var_s8($sp)
0x000011a4:  1c 00 b1 8f              lw      $s1, 0x18+var_s4($sp)
0x000011a8:  18 00 b0 8f              lw      $s0, 0x18+var_s0($sp)
0x000011ac:  01 00 02 24              li      $v0, 1
0x000011b0:  08 00 e0 03              jr      $ra
0x000011b4:  28 00 bd 27              addiu   $sp, 0x28
0x000011b8:  20 00 bf 8f              lw      $ra, 0x18+var_s8($sp)
0x000011bc:  1c 00 b1 8f              lw      $s1, 0x18+var_s4($sp)
0x000011c0:  18 00 b0 8f              lw      $s0, 0x18+var_s0($sp)
0x000011c4:  21 10 00 00              move    $v0, $zero
0x000011c8:  08 00 e0 03              jr      $ra
0x000011cc:  28 00 bd 27              addiu   $sp, 0x28
