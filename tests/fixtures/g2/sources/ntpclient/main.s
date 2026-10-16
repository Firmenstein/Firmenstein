; binary: ntpclient
; function: main
; symbol: main
; entry_ea: 0x402dd0
; source_sha256: bc96a6513183bb4ef7e7623798fbfc48c2812de570e1503a7a986a524281b1a2
; chunk: 0x402dd0-0x403860
0x00402dd0:  05 00 1c 3c 70 b2 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x00402dd8:  21 e0 99 03              addu    $gp, $t9
0x00402ddc:  28 fe bd 27              addiu   $sp, -0x1D8
0x00402de0:  d4 01 bf af              sw      $ra, 0x1B0+var_s24($sp)
0x00402de4:  d0 01 be af              sw      $fp, 0x1B0+var_s20($sp)
0x00402de8:  cc 01 b7 af              sw      $s7, 0x1B0+var_s1C($sp)
0x00402dec:  c8 01 b6 af              sw      $s6, 0x1B0+var_s18($sp)
0x00402df0:  c4 01 b5 af              sw      $s5, 0x1B0+var_s14($sp)
0x00402df4:  c0 01 b4 af              sw      $s4, 0x1B0+var_s10($sp)
0x00402df8:  bc 01 b3 af              sw      $s3, 0x1B0+var_sC($sp)
0x00402dfc:  b8 01 b2 af              sw      $s2, 0x1B0+var_s8($sp)
0x00402e00:  b4 01 b1 af              sw      $s1, 0x1B0+var_s4($sp)
0x00402e04:  b0 01 b0 af              sw      $s0, 0x1B0+var_s0($sp)
0x00402e08:  28 00 bc af              sw      $gp, 0x1B0+var_188($sp)
0x00402e0c:  21 a0 80 00              move    $s4, $a0
0x00402e10:  21 b8 a0 00              move    $s7, $a1
0x00402e14:  1c 80 90 8f              li      $s0, 0x400000
0x00402e18:  00 00 00 00              nop
0x00402e1c:  c0 5a 02 92              lbu     $v0, (byte_405AC0 - 0x400000)($s0)
0x00402e20:  00 00 00 00              nop
0x00402e24:  30 00 a2 a3              sb      $v0, 0x1B0+dest($sp)
0x00402e28:  31 00 a4 27              addiu   $a0, $sp, 0x1B0+s # s
0x00402e2c:  21 28 00 00              move    $a1, $zero # c
0x00402e30:  ff 00 06 24              li      $a2, 0xFF # n
0x00402e34:  d0 80 99 8f              la      $t9, memset
0x00402e38:  00 00 00 00              nop
0x00402e3c:  09 f8 20 03              jalr    $t9  # memset
0x00402e40:  21 88 20 03              move    $s1, $t9
0x00402e44:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00402e48:  c0 5a 02 92              lbu     $v0, (byte_405AC0 - 0x400000)($s0)
0x00402e4c:  00 00 00 00              nop
0x00402e50:  30 01 a2 a3              sb      $v0, 0x1B0+name($sp)
0x00402e54:  31 01 a4 27              addiu   $a0, $sp, 0x1B0+var_7F # s
0x00402e58:  21 28 00 00              move    $a1, $zero # c
0x00402e5c:  d0 80 99 8f              la      $t9, memset
0x00402e60:  21 c8 20 02              move    $t9, $s1
0x00402e64:  09 f8 20 03              jalr    $t9  # memset
0x00402e68:  3f 00 06 24              li      $a2, 0x3F  # '?' # n
0x00402e6c:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00402e70:  00 00 00 00              nop
0x00402e74:  1c 80 84 8f              li      $a0, 0x400000
0x00402e78:  dc 80 99 8f              la      $t9, nvram_get
0x00402e7c:  00 00 00 00              nop
0x00402e80:  09 f8 20 03              jalr    $t9  # nvram_get
0x00402e84:  b0 58 84 24              addiu   $a0, (aWanMac - 0x400000) # "wan_mac"
0x00402e88:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00402e8c:  04 00 40 14              bnez    $v0, loc_402EA0
0x00402e90:  00 00 00 00              nop
0x00402e94:  1c 80 82 8f              li      $v0, 0x400000
0x00402e98:  00 00 00 00              nop
0x00402e9c:  ec 54 42 24              addiu   $v0, (aUsageSCCountDH+0x5C - 0x400000) # ""
0x00402ea0:  60 80 99 8f              la      $t9, atoi
0x00402ea4:  00 00 00 00              nop
0x00402ea8:  09 f8 20 03              jalr    $t9  # atoi
0x00402eac:  21 20 40 00              move    $a0, $v0 # nptr
0x00402eb0:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00402eb4:  21 98 40 00              move    $s3, $v0
0x00402eb8:  1c 80 84 8f              li      $a0, 0x400000
0x00402ebc:  00 00 00 00              nop
0x00402ec0:  b8 58 84 24              addiu   $a0, (aTmpNtpFirstboo - 0x400000) # "/tmp/ntp_firstboot"
0x00402ec4:  1c 80 85 8f              li      $a1, 0x400000
0x00402ec8:  e0 80 99 8f              la      $t9, fopen
0x00402ecc:  00 00 00 00              nop
0x00402ed0:  09 f8 20 03              jalr    $t9  # fopen
0x00402ed4:  cc 58 a5 24              addiu   $a1, (aR - 0x400000) # "r"
0x00402ed8:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00402edc:  36 00 40 14              bnez    $v0, loc_402FB8
0x00402ee0:  21 90 00 00              move    $s2, $zero
0x00402ee4:  90 80 92 8f              la      $s2, stderr
0x00402ee8:  1c 80 84 8f              li      $a0, 0x400000
0x00402eec:  00 00 00 00              nop
0x00402ef0:  d0 58 84 24              addiu   $a0, (aFileTmpNtpFirs - 0x400000) # "File /tmp/ntp_firstboot not exist!, Fir"...
0x00402ef4:  01 00 05 24              li      $a1, 1 # size
0x00402ef8:  31 00 06 24              li      $a2, 0x31  # '1' # n
0x00402efc:  00 00 47 8e              lw      $a3, (stderr - 0x446E8C)($s2) # s
0x00402f00:  74 80 99 8f              la      $t9, fwrite
0x00402f04:  00 00 00 00              nop
0x00402f08:  09 f8 20 03              jalr    $t9  # fwrite
0x00402f0c:  21 88 20 03              move    $s1, $t9
0x00402f10:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00402f14:  00 00 00 00              nop
0x00402f18:  1c 80 84 8f              li      $a0, 0x400000
0x00402f1c:  00 00 00 00              nop
0x00402f20:  b8 58 84 24              addiu   $a0, (aTmpNtpFirstboo - 0x400000) # "/tmp/ntp_firstboot"
0x00402f24:  1c 80 85 8f              li      $a1, 0x400000
0x00402f28:  e0 80 99 8f              la      $t9, fopen
0x00402f2c:  00 00 00 00              nop
0x00402f30:  09 f8 20 03              jalr    $t9  # fopen
0x00402f34:  04 59 a5 24              addiu   $a1, (aW - 0x400000) # "w"
0x00402f38:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00402f3c:  0d 00 40 14              bnez    $v0, loc_402F74
0x00402f40:  21 80 40 00              move    $s0, $v0
0x00402f44:  1c 80 84 8f              li      $a0, 0x400000
0x00402f48:  00 00 00 00              nop
0x00402f4c:  08 59 84 24              addiu   $a0, (aOpenFileTmpNtp - 0x400000) # "Open file /tmp/ntp_firstboot failed.\n"
0x00402f50:  01 00 05 24              li      $a1, 1 # size
0x00402f54:  00 00 47 8e              lw      $a3, (stderr - 0x446E8C)($s2) # s
0x00402f58:  74 80 99 8f              la      $t9, fwrite
0x00402f5c:  21 c8 20 02              move    $t9, $s1
0x00402f60:  09 f8 20 03              jalr    $t9  # fwrite
0x00402f64:  25 00 06 24              li      $a2, 0x25  # '%' # n
0x00402f68:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00402f6c:  30 02 00 10              b       loc_403830
0x00402f70:  ff ff 02 24              li      $v0, 0xFFFFFFFF
0x00402f74:  1c 80 84 8f              li      $a0, 0x400000
0x00402f78:  00 00 00 00              nop
0x00402f7c:  30 59 84 24              addiu   $a0, (aFirstBooted - 0x400000) # "first booted!\n"
0x00402f80:  01 00 05 24              li      $a1, 1 # size
0x00402f84:  0e 00 06 24              li      $a2, 0xE # n
0x00402f88:  74 80 99 8f              la      $t9, fwrite
0x00402f8c:  00 00 00 00              nop
0x00402f90:  09 f8 20 03              jalr    $t9  # fwrite
0x00402f94:  21 38 40 00              move    $a3, $v0 # s
0x00402f98:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00402f9c:  00 00 00 00              nop
0x00402fa0:  c0 80 99 8f              la      $t9, fclose
0x00402fa4:  00 00 00 00              nop
0x00402fa8:  09 f8 20 03              jalr    $t9  # fclose
0x00402fac:  21 20 00 02              move    $a0, $s0 # stream
0x00402fb0:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00402fb4:  01 00 12 24              li      $s2, 1
0x00402fb8:  1c 80 84 8f              li      $a0, 0x400000
0x00402fbc:  00 00 00 00              nop
0x00402fc0:  40 59 84 24              addiu   $a0, (aVarLockNtpclie - 0x400000) # "/var/lock/ntpclient"
0x00402fc4:  50 80 99 8f              la      $t9, open
0x00402fc8:  00 00 00 00              nop
0x00402fcc:  09 f8 20 03              jalr    $t9  # open
0x00402fd0:  01 03 05 24              li      $a1, 0x301 # oflag
0x00402fd4:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00402fd8:  21 80 40 00              move    $s0, $v0
0x00402fdc:  ff ff 02 24              li      $v0, 0xFFFFFFFF
0x00402fe0:  0f 00 02 16              bne     $s0, $v0, loc_403020
0x00402fe4:  21 20 00 02              move    $a0, $s0 # fd
0x00402fe8:  1c 80 84 8f              li      $a0, 0x400000
0x00402fec:  00 00 00 00              nop
0x00402ff0:  54 59 84 24              addiu   $a0, (aCreateVarLockN - 0x400000) # "Create /var/lock/ntpclient file FAIL."
0x00402ff4:  01 00 05 24              li      $a1, 1 # size
0x00402ff8:  90 80 82 8f              la      $v0, stderr
0x00402ffc:  00 00 00 00              nop
0x00403000:  00 00 47 8c              lw      $a3, (stderr - 0x446E8C)($v0) # s
0x00403004:  74 80 99 8f              la      $t9, fwrite
0x00403008:  00 00 00 00              nop
0x0040300c:  09 f8 20 03              jalr    $t9  # fwrite
0x00403010:  25 00 06 24              li      $a2, 0x25  # '%' # n
0x00403014:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403018:  05 02 00 10              b       loc_403830
0x0040301c:  ff ff 02 24              li      $v0, 0xFFFFFFFF
0x00403020:  02 00 05 24              li      $a1, 2 # cmd
0x00403024:  c8 80 99 8f              la      $t9, lockf
0x00403028:  00 00 00 00              nop
0x0040302c:  09 f8 20 03              jalr    $t9  # lockf
0x00403030:  21 30 00 00              move    $a2, $zero # len
0x00403034:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403038:  21 88 40 00              move    $s1, $v0
0x0040303c:  ff ff 02 24              li      $v0, 0xFFFFFFFF
0x00403040:  18 00 22 16              bne     $s1, $v0, loc_4030A4
0x00403044:  00 00 00 00              nop
0x00403048:  34 80 99 8f              la      $t9, close
0x0040304c:  00 00 00 00              nop
0x00403050:  09 f8 20 03              jalr    $t9  # close
0x00403054:  21 20 00 02              move    $a0, $s0 # fd
0x00403058:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x0040305c:  03 00 51 10              beq     $v0, $s1, loc_40306C
0x00403060:  00 00 00 00              nop
0x00403064:  f2 01 00 10              b       loc_403830
0x00403068:  ff ff 02 24              li      $v0, 0xFFFFFFFF
0x0040306c:  1c 80 84 8f              li      $a0, 0x400000
0x00403070:  00 00 00 00              nop
0x00403074:  7c 59 84 24              addiu   $a0, (aCloseVarLockNt - 0x400000) # "Close /var/lock/ntpclient file FAIL."
0x00403078:  01 00 05 24              li      $a1, 1 # size
0x0040307c:  90 80 82 8f              la      $v0, stderr
0x00403080:  00 00 00 00              nop
0x00403084:  00 00 47 8c              lw      $a3, (stderr - 0x446E8C)($v0) # s
0x00403088:  74 80 99 8f              la      $t9, fwrite
0x0040308c:  00 00 00 00              nop
0x00403090:  09 f8 20 03              jalr    $t9  # fwrite
0x00403094:  24 00 06 24              li      $a2, 0x24  # '$' # n
0x00403098:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x0040309c:  e4 01 00 10              b       loc_403830
0x004030a0:  ff ff 02 24              li      $v0, 0xFFFFFFFF
0x004030a4:  12 00 40 12              beqz    $s2, loc_4030F0
0x004030a8:  00 00 00 00              nop
0x004030ac:  b8 80 99 8f              la      $t9, time
0x004030b0:  00 00 00 00              nop
0x004030b4:  09 f8 20 03              jalr    $t9  # time
0x004030b8:  74 01 a4 27              addiu   $a0, $sp, 0x1B0+timer # timer
0x004030bc:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004030c0:  74 01 a4 8f              lw      $a0, 0x1B0+timer($sp)
0x004030c4:  8c 80 99 8f              la      $t9, srandom
0x004030c8:  00 00 00 00              nop
0x004030cc:  09 f8 20 03              jalr    $t9  # srandom
0x004030d0:  21 20 64 02              addu    $a0, $s3, $a0 # seed
0x004030d4:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004030d8:  00 00 00 00              nop
0x004030dc:  94 81 99 8f              la      $t9, random
0x004030e0:  00 00 00 00              nop
0x004030e4:  09 f8 20 03              jalr    $t9  # random
0x004030e8:  00 00 00 00              nop
0x004030ec:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004030f0:  98 01 a0 af              sw      $zero, 0x1B0+var_18($sp)
0x004030f4:  a4 01 a0 af              sw      $zero, 0x1B0+var_C($sp)
0x004030f8:  03 00 02 24              li      $v0, 3
0x004030fc:  a0 01 a2 af              sw      $v0, 0x1B0+var_10($sp)
0x00403100:  9c 01 a0 af              sw      $zero, 0x1B0+var_14($sp)
0x00403104:  1c 80 82 8f              li      $v0, 0x400000
0x00403108:  00 00 00 00              nop
0x0040310c:  a4 59 56 24              addiu   $s6, $v0, (aCDhIPLrs - 0x400000) # "c:dh:i:p:lrs"
0x00403110:  30 00 b3 27              addiu   $s3, $sp, 0x1B0+dest
0x00403114:  1c 80 9e 8f              li      $fp, 0x400000
0x00403118:  1c 80 82 8f              li      $v0, 0x400000
0x0040311c:  00 00 00 00              nop
0x00403120:  b4 59 55 24              addiu   $s5, $v0, (aH - 0x400000) # "-h"
0x00403124:  21 20 80 02              move    $a0, $s4 # argc
0x00403128:  21 28 e0 02              move    $a1, $s7 # argv
0x0040312c:  d8 80 99 8f              la      $t9, getopt
0x00403130:  00 00 00 00              nop
0x00403134:  09 f8 20 03              jalr    $t9  # getopt
0x00403138:  21 30 c0 02              move    $a2, $s6 # shortopts
0x0040313c:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403140:  21 18 40 00              move    $v1, $v0
0x00403144:  ff ff 02 24              li      $v0, 0xFFFFFFFF
0x00403148:  90 00 62 10              beq     $v1, $v0, loc_40338C
0x0040314c:  9d ff 63 24              addiu   $v1, -0x63 # switch 17 cases
0x00403150:  11 00 62 2c              sltiu   $v0, $v1, 0x11
0x00403154:  82 00 40 10              beqz    $v0, def_403178 # jumptable 00403178 default case, cases 101-103,106,107,109-111,113
0x00403158:  80 10 03 00              sll     $v0, $v1, 2
0x0040315c:  1c 80 83 8f              li      $v1, 0x400000
0x00403160:  00 00 00 00              nop
0x00403164:  c0 5b 63 24              addiu   $v1, (jpt_403178 - 0x400000)
0x00403168:  21 10 43 00              addu    $v0, $v1
0x0040316c:  00 00 42 8c              lw      $v0, 0($v0)
0x00403170:  00 00 00 00              nop
0x00403174:  21 10 5c 00              addu    $v0, $gp
0x00403178:  08 00 40 00              jr      $v0 # switch jump
0x0040317c:  00 00 00 00              nop
0x00403180:  14 00 80 1e              bgtz    $s4, loc_4031D4 # jumptable 00403178 case 104
0x00403184:  21 90 00 00              move    $s2, $zero
0x00403188:  1f 00 00 10              b       loc_403208
0x0040318c:  01 00 51 26              addiu   $s1, $s2, 1
0x00403190:  5c 81 99 8f              la      $t9, optarg # jumptable 00403178 case 99
0x00403194:  00 00 00 00              nop
0x00403198:  00 00 24 8f              lw      $a0, (optarg - 0x446F10)($t9) # nptr
0x0040319c:  60 80 99 8f              la      $t9, atoi
0x004031a0:  00 00 00 00              nop
0x004031a4:  09 f8 20 03              jalr    $t9  # atoi
0x004031a8:  00 00 00 00              nop
0x004031ac:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004031b0:  dc ff 00 10              b       loc_403124
0x004031b4:  9c 01 a2 af              sw      $v0, 0x1B0+var_14($sp)
0x004031b8:  44 81 83 8f              la      $v1, debug # jumptable 00403178 case 100
0x004031bc:  00 00 00 00              nop
0x004031c0:  00 00 62 8c              lw      $v0, (debug - 0x446238)($v1)
0x004031c4:  00 00 00 00              nop
0x004031c8:  01 00 42 24              addiu   $v0, 1
0x004031cc:  d5 ff 00 10              b       loc_403124
0x004031d0:  00 00 62 ac              sw      $v0, (debug - 0x446238)($v1)
0x004031d4:  21 80 e0 02              move    $s0, $s7
0x004031d8:  00 00 04 8e              lw      $a0, 0($s0) # s1
0x004031dc:  a8 80 99 8f              la      $t9, strcmp
0x004031e0:  00 00 00 00              nop
0x004031e4:  09 f8 20 03              jalr    $t9  # strcmp
0x004031e8:  21 28 a0 02              move    $a1, $s5 # s2
0x004031ec:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004031f0:  05 00 40 10              beqz    $v0, loc_403208
0x004031f4:  01 00 51 26              addiu   $s1, $s2, 1
0x004031f8:  01 00 52 26              addiu   $s2, 1
0x004031fc:  f6 ff 54 16              bne     $s2, $s4, loc_4031D8
0x00403200:  04 00 10 26              addiu   $s0, 4
0x00403204:  01 00 51 26              addiu   $s1, $s2, 1
0x00403208:  2a 10 34 02              slt     $v0, $s1, $s4
0x0040320c:  c5 ff 40 10              beqz    $v0, loc_403124
0x00403210:  80 10 11 00              sll     $v0, $s1, 2
0x00403214:  21 10 57 00              addu    $v0, $s7
0x00403218:  00 00 45 8c              lw      $a1, 0($v0)
0x0040321c:  00 00 00 00              nop
0x00403220:  00 00 a3 80              lb      $v1, 0($a1)
0x00403224:  2d 00 02 24              li      $v0, 0x2D  # '-'
0x00403228:  be ff 62 10              beq     $v1, $v0, loc_403124
0x0040322c:  80 10 12 00              sll     $v0, $s2, 2
0x00403230:  07 00 00 10              b       loc_403250
0x00403234:  21 80 57 00              addu    $s0, $v0, $s7
0x00403238:  08 00 05 8e              lw      $a1, 8($s0) # src
0x0040323c:  00 00 00 00              nop
0x00403240:  00 00 a3 80              lb      $v1, 0($a1)
0x00403244:  00 00 00 00              nop
0x00403248:  b6 ff 62 10              beq     $v1, $v0, loc_403124
0x0040324c:  04 00 10 26              addiu   $s0, 4
0x00403250:  21 20 60 02              move    $a0, $s3 # dest
0x00403254:  ec 80 99 8f              la      $t9, strncat
0x00403258:  00 00 00 00              nop
0x0040325c:  09 f8 20 03              jalr    $t9  # strncat
0x00403260:  00 01 06 24              li      $a2, 0x100 # n
0x00403264:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403268:  00 00 00 00              nop
0x0040326c:  54 80 99 8f              la      $t9, strlen
0x00403270:  00 00 00 00              nop
0x00403274:  09 f8 20 03              jalr    $t9  # strlen
0x00403278:  21 20 60 02              move    $a0, $s3 # s
0x0040327c:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403280:  21 10 62 02              addu    $v0, $s3, $v0
0x00403284:  b8 59 c3 93              lbu     $v1, (asc_4059B8 - 0x400000)($fp) # " "
0x00403288:  00 00 00 00              nop
0x0040328c:  00 00 43 a0              sb      $v1, 0($v0)
0x00403290:  1c 80 84 8f              li      $a0, 0x400000
0x00403294:  00 00 00 00              nop
0x00403298:  b8 59 84 24              addiu   $a0, (asc_4059B8 - 0x400000) # " "
0x0040329c:  01 00 83 90              lbu     $v1, (asc_4059B8+1 - 0x4059B8)($a0) # ""
0x004032a0:  00 00 00 00              nop
0x004032a4:  01 00 43 a0              sb      $v1, 1($v0)
0x004032a8:  01 00 31 26              addiu   $s1, 1
0x004032ac:  2a 10 34 02              slt     $v0, $s1, $s4
0x004032b0:  e1 ff 40 14              bnez    $v0, loc_403238
0x004032b4:  2d 00 02 24              li      $v0, 0x2D  # '-'
0x004032b8:  9b ff 00 10              b       loc_403128
0x004032bc:  21 20 80 02              move    $a0, $s4
0x004032c0:  5c 81 99 8f              la      $t9, optarg # jumptable 00403178 case 105
0x004032c4:  00 00 00 00              nop
0x004032c8:  00 00 24 8f              lw      $a0, (optarg - 0x446F10)($t9) # nptr
0x004032cc:  60 80 99 8f              la      $t9, atoi
0x004032d0:  00 00 00 00              nop
0x004032d4:  09 f8 20 03              jalr    $t9  # atoi
0x004032d8:  00 00 00 00              nop
0x004032dc:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004032e0:  90 ff 00 10              b       loc_403124
0x004032e4:  a0 01 a2 af              sw      $v0, 0x1B0+var_10($sp)
0x004032e8:  70 80 83 8f              la      $v1, live # jumptable 00403178 case 108
0x004032ec:  00 00 00 00              nop
0x004032f0:  00 00 62 8c              lw      $v0, (live - 0x446230)($v1)
0x004032f4:  00 00 00 00              nop
0x004032f8:  01 00 42 24              addiu   $v0, 1
0x004032fc:  89 ff 00 10              b       loc_403124
0x00403300:  00 00 62 ac              sw      $v0, (live - 0x446230)($v1)
0x00403304:  5c 81 99 8f              la      $t9, optarg # jumptable 00403178 case 112
0x00403308:  00 00 00 00              nop
0x0040330c:  00 00 24 8f              lw      $a0, (optarg - 0x446F10)($t9) # nptr
0x00403310:  60 80 99 8f              la      $t9, atoi
0x00403314:  00 00 00 00              nop
0x00403318:  09 f8 20 03              jalr    $t9  # atoi
0x0040331c:  00 00 00 00              nop
0x00403320:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403324:  00 14 02 00              sll     $v0, 16
0x00403328:  03 14 02 00              sra     $v0, 16
0x0040332c:  7d ff 00 10              b       loc_403124
0x00403330:  a4 01 a2 af              sw      $v0, 0x1B0+var_C($sp)
0x00403334:  98 01 a2 8f              lw      $v0, 0x1B0+var_18($sp) # jumptable 00403178 case 114
0x00403338:  00 00 00 00              nop
0x0040333c:  01 00 42 24              addiu   $v0, 1
0x00403340:  78 ff 00 10              b       loc_403124
0x00403344:  98 01 a2 af              sw      $v0, 0x1B0+var_18($sp)
0x00403348:  01 00 02 24              li      $v0, 1 # jumptable 00403178 case 115
0x0040334c:  a4 80 83 8f              la      $v1, set_clock
0x00403350:  00 00 00 00              nop
0x00403354:  00 00 62 ac              sw      $v0, (set_clock - 0x446234)($v1)
0x00403358:  72 ff 00 10              b       loc_403124
0x0040335c:  9c 01 a2 af              sw      $v0, 0x1B0+var_14($sp)
0x00403360:  00 00 e4 8e              lw      $a0, 0($s7) # jumptable 00403178 default case, cases 101-103,106,107,109-111,113
0x00403364:  74 81 99 8f              la      $t9, usage
0x00403368:  00 00 00 00              nop
0x0040336c:  09 f8 20 03              jalr    $t9  # usage
0x00403370:  00 00 00 00              nop
0x00403374:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403378:  00 00 00 00              nop
0x0040337c:  6c 80 99 8f              la      $t9, exit
0x00403380:  00 00 00 00              nop
0x00403384:  09 f8 20 03              jalr    $t9  # exit
0x00403388:  01 00 04 24              li      $a0, 1 # status
0x0040338c:  98 01 a4 8f              lw      $a0, 0x1B0+var_18($sp)
0x00403390:  00 00 00 00              nop
0x00403394:  0b 00 80 10              beqz    $a0, loc_4033C4
0x00403398:  00 00 00 00              nop
0x0040339c:  24 81 99 8f              la      $t9, do_replay
0x004033a0:  00 00 00 00              nop
0x004033a4:  09 f8 20 03              jalr    $t9  # do_replay
0x004033a8:  00 00 00 00              nop
0x004033ac:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004033b0:  00 00 00 00              nop
0x004033b4:  6c 80 99 8f              la      $t9, exit
0x004033b8:  00 00 00 00              nop
0x004033bc:  09 f8 20 03              jalr    $t9  # exit
0x004033c0:  21 20 00 00              move    $a0, $zero # status
0x004033c4:  44 81 82 8f              la      $v0, debug
0x004033c8:  00 00 00 00              nop
0x004033cc:  00 00 47 8c              lw      $a3, (debug - 0x446238)($v0)
0x004033d0:  00 00 00 00              nop
0x004033d4:  22 00 e0 10              beqz    $a3, loc_403460
0x004033d8:  30 00 a2 27              addiu   $v0, $sp, 0x1B0+dest
0x004033dc:  90 80 90 8f              la      $s0, stderr
0x004033e0:  00 00 00 00              nop
0x004033e4:  00 00 04 8e              lw      $a0, (stderr - 0x446E8C)($s0) # stream
0x004033e8:  10 00 a2 af              sw      $v0, 0x1B0+var_1A0($sp)
0x004033ec:  a0 01 b9 8f              lw      $t9, 0x1B0+var_10($sp)
0x004033f0:  00 00 00 00              nop
0x004033f4:  14 00 b9 af              sw      $t9, 0x1B0+var_19C($sp)
0x004033f8:  70 80 82 8f              la      $v0, live
0x004033fc:  00 00 00 00              nop
0x00403400:  00 00 42 8c              lw      $v0, (live - 0x446230)($v0)
0x00403404:  00 00 00 00              nop
0x00403408:  18 00 a2 af              sw      $v0, 0x1B0+var_198($sp)
0x0040340c:  a4 01 a2 8f              lw      $v0, 0x1B0+var_C($sp)
0x00403410:  00 00 00 00              nop
0x00403414:  1c 00 a2 af              sw      $v0, 0x1B0+var_194($sp)
0x00403418:  a4 80 82 8f              la      $v0, set_clock
0x0040341c:  00 00 00 00              nop
0x00403420:  00 00 42 8c              lw      $v0, (set_clock - 0x446234)($v0)
0x00403424:  00 00 00 00              nop
0x00403428:  20 00 a2 af              sw      $v0, 0x1B0+var_190($sp)
0x0040342c:  1c 80 85 8f              li      $a1, 0x400000
0x00403430:  9c 01 a6 8f              lw      $a2, 0x1B0+var_14($sp)
0x00403434:  2c 81 99 8f              la      $t9, fprintf
0x00403438:  00 00 00 00              nop
0x0040343c:  09 f8 20 03              jalr    $t9  # fprintf
0x00403440:  bc 59 a5 24              addiu   $a1, (aConfigurationC - 0x400000) # "Configuration:\n  -c probe_count %d\n  "...
0x00403444:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403448:  00 00 04 8e              lw      $a0, (stderr - 0x446E8C)($s0) # stream
0x0040344c:  48 81 99 8f              la      $t9, fflush
0x00403450:  00 00 00 00              nop
0x00403454:  09 f8 20 03              jalr    $t9  # fflush
0x00403458:  00 00 00 00              nop
0x0040345c:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403460:  21 20 00 00              move    $a0, $zero # timer
0x00403464:  b8 80 99 8f              la      $t9, time
0x00403468:  00 00 00 00              nop
0x0040346c:  09 f8 20 03              jalr    $t9  # time
0x00403470:  21 80 20 03              move    $s0, $t9
0x00403474:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403478:  00 00 00 00              nop
0x0040347c:  80 80 83 8f              la      $v1, bkf_start
0x00403480:  00 00 00 00              nop
0x00403484:  00 00 62 ac              sw      $v0, (bkf_start - 0x446204)($v1)
0x00403488:  b8 80 99 8f              la      $t9, time
0x0040348c:  21 c8 00 02              move    $t9, $s0
0x00403490:  09 f8 20 03              jalr    $t9  # time
0x00403494:  21 20 00 00              move    $a0, $zero # timer
0x00403498:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x0040349c:  00 00 00 00              nop
0x004034a0:  20 81 83 8f              la      $v1, bkf_current
0x004034a4:  00 00 00 00              nop
0x004034a8:  00 00 62 ac              sw      $v0, (bkf_current - 0x4461FC)($v1)
0x004034ac:  3c 00 03 24              li      $v1, 0x3C  # '<'
0x004034b0:  fc 80 82 8f              la      $v0, bkf_interval
0x004034b4:  00 00 00 00              nop
0x004034b8:  00 00 43 ac              sw      $v1, (bkf_interval - 0x446200)($v0)
0x004034bc:  88 01 a0 af              sw      $zero, 0x1B0+var_28($sp)
0x004034c0:  8c 01 a0 af              sw      $zero, 0x1B0+var_24($sp)
0x004034c4:  90 01 a0 af              sw      $zero, 0x1B0+var_20($sp)
0x004034c8:  94 01 a0 af              sw      $zero, 0x1B0+var_1C($sp)
0x004034cc:  02 00 02 24              li      $v0, 2
0x004034d0:  7c 01 a2 af              sw      $v0, 0x1B0+var_34($sp)
0x004034d4:  01 00 02 24              li      $v0, 1
0x004034d8:  80 01 a2 af              sw      $v0, 0x1B0+var_30($sp)
0x004034dc:  78 01 a0 af              sw      $zero, 0x1B0+var_38($sp)
0x004034e0:  84 01 a0 af              sw      $zero, 0x1B0+var_2C($sp)
0x004034e4:  30 00 b0 27              addiu   $s0, $sp, 0x1B0+dest
0x004034e8:  21 20 00 02              move    $a0, $s0 # s
0x004034ec:  1c 80 92 8f              li      $s2, 0x400000
0x004034f0:  58 80 99 8f              la      $t9, strspn
0x004034f4:  00 00 00 00              nop
0x004034f8:  09 f8 20 03              jalr    $t9  # strspn
0x004034fc:  b8 59 45 26              addiu   $a1, $s2, (asc_4059B8 - 0x400000) # " "
0x00403500:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403504:  21 98 02 02              addu    $s3, $s0, $v0
0x00403508:  30 01 b1 27              addiu   $s1, $sp, 0x1B0+name
0x0040350c:  21 20 20 02              move    $a0, $s1 # dest
0x00403510:  21 28 60 02              move    $a1, $s3 # src
0x00403514:  08 81 99 8f              la      $t9, strncpy
0x00403518:  00 00 00 00              nop
0x0040351c:  09 f8 20 03              jalr    $t9  # strncpy
0x00403520:  40 00 06 24              li      $a2, 0x40  # '@' # n
0x00403524:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403528:  21 20 20 02              move    $a0, $s1 # s
0x0040352c:  94 80 99 8f              la      $t9, strcspn
0x00403530:  00 00 00 00              nop
0x00403534:  09 f8 20 03              jalr    $t9  # strcspn
0x00403538:  b8 59 45 26              addiu   $a1, $s2, (asc_4059B8 - 0x400000) # " "
0x0040353c:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403540:  21 80 02 02              addu    $s0, $v0
0x00403544:  00 01 00 a2              sb      $zero, 0x100($s0)
0x00403548:  6f 01 a0 a3              sb      $zero, 0x1B0+var_41($sp)
0x0040354c:  21 20 60 02              move    $a0, $s3 # s
0x00403550:  4c 80 99 8f              la      $t9, strchr
0x00403554:  00 00 00 00              nop
0x00403558:  09 f8 20 03              jalr    $t9  # strchr
0x0040355c:  20 00 05 24              li      $a1, 0x20  # ' ' # c
0x00403560:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403564:  21 88 40 00              move    $s1, $v0
0x00403568:  30 01 a2 83              lb      $v0, 0x1B0+name($sp)
0x0040356c:  00 00 00 00              nop
0x00403570:  ae 00 40 10              beqz    $v0, loc_40382C
0x00403574:  30 01 b3 27              addiu   $s3, $sp, 0x1B0+name
0x00403578:  1c 80 82 8f              li      $v0, 0x400000
0x0040357c:  00 00 00 00              nop
0x00403580:  58 5a 54 24              addiu   $s4, $v0, (a6 - 0x400000) # "6"
0x00403584:  1c 80 97 8f              li      $s7, 0x400000
0x00403588:  78 01 a2 27              addiu   $v0, $sp, 0x1B0+var_38
0x0040358c:  a8 01 a2 af              sw      $v0, 0x1B0+req($sp)
0x00403590:  70 01 a3 27              addiu   $v1, $sp, 0x1B0+var_40
0x00403594:  ac 01 a3 af              sw      $v1, 0x1B0+pai($sp)
0x00403598:  21 a8 40 02              move    $s5, $s2
0x0040359c:  1c 80 82 8f              li      $v0, 0x400000
0x004035a0:  00 00 00 00              nop
0x004035a4:  ec 54 5e 24              addiu   $fp, $v0, (aUsageSCCountDH+0x5C - 0x400000) # ""
0x004035a8:  30 00 b6 27              addiu   $s6, $sp, 0x1B0+dest
0x004035ac:  21 20 60 02              move    $a0, $s3 # s1
0x004035b0:  a8 80 99 8f              la      $t9, strcmp
0x004035b4:  00 00 00 00              nop
0x004035b8:  09 f8 20 03              jalr    $t9  # strcmp
0x004035bc:  21 28 80 02              move    $a1, $s4 # s2
0x004035c0:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004035c4:  0c 00 40 14              bnez    $v0, loc_4035F8
0x004035c8:  21 20 60 02              move    $a0, $s3 # s1
0x004035cc:  88 01 a0 af              sw      $zero, 0x1B0+var_28($sp)
0x004035d0:  8c 01 a0 af              sw      $zero, 0x1B0+var_24($sp)
0x004035d4:  90 01 a0 af              sw      $zero, 0x1B0+var_20($sp)
0x004035d8:  94 01 a0 af              sw      $zero, 0x1B0+var_1C($sp)
0x004035dc:  0a 00 02 24              li      $v0, 0xA
0x004035e0:  7c 01 a2 af              sw      $v0, 0x1B0+var_34($sp)
0x004035e4:  01 00 02 24              li      $v0, 1
0x004035e8:  80 01 a2 af              sw      $v0, 0x1B0+var_30($sp)
0x004035ec:  78 01 a0 af              sw      $zero, 0x1B0+var_38($sp)
0x004035f0:  69 00 00 10              b       loc_403798
0x004035f4:  84 01 a0 af              sw      $zero, 0x1B0+var_2C($sp)
0x004035f8:  a8 80 99 8f              la      $t9, strcmp
0x004035fc:  00 00 00 00              nop
0x00403600:  09 f8 20 03              jalr    $t9  # strcmp
0x00403604:  5c 5a e5 26              addiu   $a1, $s7, (a4 - 0x400000) # "4"
0x00403608:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x0040360c:  0c 00 40 14              bnez    $v0, loc_403640
0x00403610:  21 20 60 02              move    $a0, $s3 # name
0x00403614:  88 01 a0 af              sw      $zero, 0x1B0+var_28($sp)
0x00403618:  8c 01 a0 af              sw      $zero, 0x1B0+var_24($sp)
0x0040361c:  90 01 a0 af              sw      $zero, 0x1B0+var_20($sp)
0x00403620:  94 01 a0 af              sw      $zero, 0x1B0+var_1C($sp)
0x00403624:  02 00 02 24              li      $v0, 2
0x00403628:  7c 01 a2 af              sw      $v0, 0x1B0+var_34($sp)
0x0040362c:  01 00 02 24              li      $v0, 1
0x00403630:  80 01 a2 af              sw      $v0, 0x1B0+var_30($sp)
0x00403634:  78 01 a0 af              sw      $zero, 0x1B0+var_38($sp)
0x00403638:  57 00 00 10              b       loc_403798
0x0040363c:  84 01 a0 af              sw      $zero, 0x1B0+var_2C($sp)
0x00403640:  a8 01 a6 8f              lw      $a2, 0x1B0+req($sp) # req
0x00403644:  ac 01 a7 8f              lw      $a3, 0x1B0+pai($sp) # pai
0x00403648:  7c 80 99 8f              la      $t9, getaddrinfo
0x0040364c:  00 00 00 00              nop
0x00403650:  09 f8 20 03              jalr    $t9  # getaddrinfo
0x00403654:  21 28 00 00              move    $a1, $zero # service
0x00403658:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x0040365c:  05 00 40 10              beqz    $v0, loc_403674
0x00403660:  00 00 00 00              nop
0x00403664:  6c 80 99 8f              la      $t9, exit
0x00403668:  00 00 00 00              nop
0x0040366c:  09 f8 20 03              jalr    $t9  # exit
0x00403670:  01 00 04 24              li      $a0, 1 # status
0x00403674:  70 01 a2 8f              lw      $v0, 0x1B0+var_40($sp)
0x00403678:  00 00 00 00              nop
0x0040367c:  04 00 44 8c              lw      $a0, 4($v0) # domain
0x00403680:  02 00 02 24              li      $v0, 2
0x00403684:  02 00 82 10              beq     $a0, $v0, loc_403690
0x00403688:  04 00 12 24              li      $s2, 4
0x0040368c:  06 00 12 24              li      $s2, 6
0x00403690:  01 00 05 24              li      $a1, 1 # type
0x00403694:  50 81 99 8f              la      $t9, socket
0x00403698:  00 00 00 00              nop
0x0040369c:  09 f8 20 03              jalr    $t9  # socket
0x004036a0:  11 00 06 24              li      $a2, 0x11 # protocol
0x004036a4:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004036a8:  21 80 40 00              move    $s0, $v0
0x004036ac:  ff ff 02 24              li      $v0, 0xFFFFFFFF
0x004036b0:  0c 00 02 16              bne     $s0, $v0, loc_4036E4
0x004036b4:  21 28 00 00              move    $a1, $zero
0x004036b8:  1c 80 84 8f              li      $a0, 0x400000
0x004036bc:  64 81 99 8f              la      $t9, perror
0x004036c0:  00 00 00 00              nop
0x004036c4:  09 f8 20 03              jalr    $t9  # perror
0x004036c8:  60 5a 84 24              addiu   $a0, (aSocket_0 - 0x400000) # "socket"
0x004036cc:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004036d0:  00 00 00 00              nop
0x004036d4:  6c 80 99 8f              la      $t9, exit
0x004036d8:  00 00 00 00              nop
0x004036dc:  09 f8 20 03              jalr    $t9  # exit
0x004036e0:  01 00 04 24              li      $a0, 1 # status
0x004036e4:  21 20 00 02              move    $a0, $s0 # fd
0x004036e8:  a4 01 a6 8f              lw      $a2, 0x1B0+var_C($sp)
0x004036ec:  30 80 99 8f              la      $t9, setup_receive
0x004036f0:  00 00 00 00              nop
0x004036f4:  09 f8 20 03              jalr    $t9  # setup_receive
0x004036f8:  21 38 40 02              move    $a3, $s2
0x004036fc:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403700:  21 20 00 02              move    $a0, $s0 # fd
0x00403704:  21 28 60 02              move    $a1, $s3
0x00403708:  7b 00 06 24              li      $a2, 0x7B  # '{'
0x0040370c:  70 81 99 8f              la      $t9, setup_transmit
0x00403710:  00 00 00 00              nop
0x00403714:  09 f8 20 03              jalr    $t9  # setup_transmit
0x00403718:  21 38 40 02              move    $a3, $s2
0x0040371c:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403720:  08 00 40 10              beqz    $v0, loc_403744
0x00403724:  00 00 00 00              nop
0x00403728:  34 80 99 8f              la      $t9, close
0x0040372c:  00 00 00 00              nop
0x00403730:  09 f8 20 03              jalr    $t9  # close
0x00403734:  21 20 00 02              move    $a0, $s0 # fd
0x00403738:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x0040373c:  16 00 00 10              b       loc_403798
0x00403740:  00 00 00 00              nop
0x00403744:  9c 01 a5 8f              lw      $a1, 0x1B0+var_14($sp)
0x00403748:  a0 01 a6 8f              lw      $a2, 0x1B0+var_10($sp)
0x0040374c:  38 80 99 8f              la      $t9, primary_loop
0x00403750:  00 00 00 00              nop
0x00403754:  09 f8 20 03              jalr    $t9  # primary_loop
0x00403758:  21 20 00 02              move    $a0, $s0
0x0040375c:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403760:  08 00 40 14              bnez    $v0, loc_403784
0x00403764:  00 00 00 00              nop
0x00403768:  34 80 99 8f              la      $t9, close
0x0040376c:  00 00 00 00              nop
0x00403770:  09 f8 20 03              jalr    $t9  # close
0x00403774:  21 20 00 02              move    $a0, $s0 # fd
0x00403778:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x0040377c:  2c 00 00 10              b       loc_403830
0x00403780:  21 10 00 00              move    $v0, $zero
0x00403784:  34 80 99 8f              la      $t9, close
0x00403788:  00 00 00 00              nop
0x0040378c:  09 f8 20 03              jalr    $t9  # close
0x00403790:  21 20 00 02              move    $a0, $s0 # fd
0x00403794:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403798:  03 00 20 16              bnez    $s1, loc_4037A8
0x0040379c:  21 20 20 02              move    $a0, $s1 # s
0x004037a0:  07 00 00 10              b       loc_4037C0
0x004037a4:  21 80 c0 03              move    $s0, $fp
0x004037a8:  58 80 99 8f              la      $t9, strspn
0x004037ac:  00 00 00 00              nop
0x004037b0:  09 f8 20 03              jalr    $t9  # strspn
0x004037b4:  b8 59 a5 26              addiu   $a1, $s5, (asc_4059B8 - 0x400000) # " "
0x004037b8:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004037bc:  21 80 51 00              addu    $s0, $v0, $s1
0x004037c0:  21 20 60 02              move    $a0, $s3 # dest
0x004037c4:  21 28 00 02              move    $a1, $s0 # src
0x004037c8:  08 81 99 8f              la      $t9, strncpy
0x004037cc:  00 00 00 00              nop
0x004037d0:  09 f8 20 03              jalr    $t9  # strncpy
0x004037d4:  40 00 06 24              li      $a2, 0x40  # '@' # n
0x004037d8:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004037dc:  21 20 60 02              move    $a0, $s3 # s
0x004037e0:  94 80 99 8f              la      $t9, strcspn
0x004037e4:  00 00 00 00              nop
0x004037e8:  09 f8 20 03              jalr    $t9  # strcspn
0x004037ec:  b8 59 a5 26              addiu   $a1, $s5, (asc_4059B8 - 0x400000) # " "
0x004037f0:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x004037f4:  21 10 c2 02              addu    $v0, $s6, $v0
0x004037f8:  00 01 40 a0              sb      $zero, 0x100($v0)
0x004037fc:  6f 01 a0 a3              sb      $zero, 0x1B0+var_41($sp)
0x00403800:  21 20 00 02              move    $a0, $s0 # s
0x00403804:  4c 80 99 8f              la      $t9, strchr
0x00403808:  00 00 00 00              nop
0x0040380c:  09 f8 20 03              jalr    $t9  # strchr
0x00403810:  20 00 05 24              li      $a1, 0x20  # ' ' # c
0x00403814:  28 00 bc 8f              lw      $gp, 0x1B0+var_188($sp)
0x00403818:  21 88 40 00              move    $s1, $v0
0x0040381c:  30 01 a2 83              lb      $v0, 0x1B0+name($sp)
0x00403820:  00 00 00 00              nop
0x00403824:  62 ff 40 14              bnez    $v0, loc_4035B0
0x00403828:  21 20 60 02              move    $a0, $s3
0x0040382c:  01 00 02 24              li      $v0, 1
0x00403830:  d4 01 bf 8f              lw      $ra, 0x1B0+var_s24($sp)
0x00403834:  d0 01 be 8f              lw      $fp, 0x1B0+var_s20($sp)
0x00403838:  cc 01 b7 8f              lw      $s7, 0x1B0+var_s1C($sp)
0x0040383c:  c8 01 b6 8f              lw      $s6, 0x1B0+var_s18($sp)
0x00403840:  c4 01 b5 8f              lw      $s5, 0x1B0+var_s14($sp)
0x00403844:  c0 01 b4 8f              lw      $s4, 0x1B0+var_s10($sp)
0x00403848:  bc 01 b3 8f              lw      $s3, 0x1B0+var_sC($sp)
0x0040384c:  b8 01 b2 8f              lw      $s2, 0x1B0+var_s8($sp)
0x00403850:  b4 01 b1 8f              lw      $s1, 0x1B0+var_s4($sp)
0x00403854:  b0 01 b0 8f              lw      $s0, 0x1B0+var_s0($sp)
0x00403858:  08 00 e0 03              jr      $ra
0x0040385c:  d8 01 bd 27              addiu   $sp, 0x1D8
