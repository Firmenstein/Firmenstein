; binary: libnvram.so
; function: nvram_get
; symbol: nvram_get
; entry_ea: 0x2150
; source_sha256: 6e90b0a95384f6ced071e1ee1d0aefcc3ccc0ef07074ccf142073d9d07de418f
; chunk: 0x2150-0x2294
0x00002150:  05 00 1c 3c f0 94 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x00002158:  21 e0 99 03              addu    $gp, $t9
0x0000215c:  68 ff bd 27              addiu   $sp, -0x98
0x00002160:  90 00 bf af              sw      $ra, 0x80+var_s10($sp)
0x00002164:  8c 00 b3 af              sw      $s3, 0x80+var_sC($sp)
0x00002168:  88 00 b2 af              sw      $s2, 0x80+var_s8($sp)
0x0000216c:  84 00 b1 af              sw      $s1, 0x80+var_s4($sp)
0x00002170:  80 00 b0 af              sw      $s0, 0x80+var_s0($sp)
0x00002174:  10 00 bc af              sw      $gp, 0x80+var_70($sp)
0x00002178:  40 80 99 8f              la      $t9, strlen
0x0000217c:  00 00 00 00              nop
0x00002180:  09 f8 20 03              jalr    $t9  # strlen
0x00002184:  21 90 80 00              move    $s2, $a0
0x00002188:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x0000218c:  21 20 00 00              move    $a0, $zero
0x00002190:  38 80 99 8f              la      $t9, nvram_init
0x00002194:  00 00 00 00              nop
0x00002198:  09 f8 20 03              jalr    $t9  # nvram_init
0x0000219c:  21 80 40 00              move    $s0, $v0
0x000021a0:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x000021a4:  24 00 40 14              bnez    $v0, loc_2238
0x000021a8:  01 00 10 26              addiu   $s0, 1
0x000021ac:  65 00 02 2e              sltiu   $v0, $s0, 0x65  # 'e'
0x000021b0:  2f 00 40 10              beqz    $v0, loc_2270
0x000021b4:  18 00 b3 27              addiu   $s3, $sp, 0x80+var_68
0x000021b8:  21 88 60 02              move    $s1, $s3
0x000021bc:  ac 80 99 8f              la      $t9, strcpy
0x000021c0:  21 28 40 02              move    $a1, $s2
0x000021c4:  09 f8 20 03              jalr    $t9  # strcpy
0x000021c8:  21 20 20 02              move    $a0, $s1
0x000021cc:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x000021d0:  21 30 00 02              move    $a2, $s0
0x000021d4:  1c 80 82 8f              li      $v0, 0x40000
0x000021d8:  7c 80 99 8f              la      $t9, read
0x000021dc:  90 31 44 8c              lw      $a0, (_fdata - 0x40000)($v0)
0x000021e0:  09 f8 20 03              jalr    $t9  # read
0x000021e4:  21 28 20 02              move    $a1, $s1
0x000021e8:  04 00 03 24              li      $v1, 4
0x000021ec:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x000021f0:  1a 00 43 10              beq     $v0, $v1, loc_225C
0x000021f4:  00 00 00 00              nop
0x000021f8:  21 80 00 00              move    $s0, $zero
0x000021fc:  07 00 33 12              beq     $s1, $s3, loc_221C
0x00002200:  21 10 00 02              move    $v0, $s0
0x00002204:  2c 80 99 8f              la      $t9, free
0x00002208:  00 00 00 00              nop
0x0000220c:  09 f8 20 03              jalr    $t9  # free
0x00002210:  21 20 20 02              move    $a0, $s1
0x00002214:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x00002218:  21 10 00 02              move    $v0, $s0
0x0000221c:  90 00 bf 8f              lw      $ra, 0x80+var_s10($sp)
0x00002220:  8c 00 b3 8f              lw      $s3, 0x80+var_sC($sp)
0x00002224:  88 00 b2 8f              lw      $s2, 0x80+var_s8($sp)
0x00002228:  84 00 b1 8f              lw      $s1, 0x80+var_s4($sp)
0x0000222c:  80 00 b0 8f              lw      $s0, 0x80+var_s0($sp)
0x00002230:  08 00 e0 03              jr      $ra
0x00002234:  98 00 bd 27              addiu   $sp, 0x98
0x00002238:  21 80 00 00              move    $s0, $zero
0x0000223c:  21 10 00 02              move    $v0, $s0
0x00002240:  90 00 bf 8f              lw      $ra, 0x80+var_s10($sp)
0x00002244:  8c 00 b3 8f              lw      $s3, 0x80+var_sC($sp)
0x00002248:  88 00 b2 8f              lw      $s2, 0x80+var_s8($sp)
0x0000224c:  84 00 b1 8f              lw      $s1, 0x80+var_s4($sp)
0x00002250:  80 00 b0 8f              lw      $s0, 0x80+var_s0($sp)
0x00002254:  08 00 e0 03              jr      $ra
0x00002258:  98 00 bd 27              addiu   $sp, 0x98
0x0000225c:  1c 80 83 8f              li      $v1, 0x40000
0x00002260:  00 00 22 8e              lw      $v0, 0($s1)
0x00002264:  f0 36 64 8c              lw      $a0, (dword_436F0 - 0x40000)($v1)
0x00002268:  e4 ff 00 10              b       loc_21FC
0x0000226c:  21 80 44 00              addu    $s0, $v0, $a0
0x00002270:  94 80 99 8f              la      $t9, malloc
0x00002274:  00 00 00 00              nop
0x00002278:  09 f8 20 03              jalr    $t9  # malloc
0x0000227c:  21 20 00 02              move    $a0, $s0
0x00002280:  10 00 bc 8f              lw      $gp, 0x80+var_70($sp)
0x00002284:  ec ff 40 10              beqz    $v0, loc_2238
0x00002288:  21 88 40 00              move    $s1, $v0
0x0000228c:  cb ff 00 10              b       loc_21BC
0x00002290:  00 00 00 00              nop
