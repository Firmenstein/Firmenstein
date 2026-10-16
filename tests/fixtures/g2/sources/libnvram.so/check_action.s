; binary: libnvram.so
; function: check_action
; symbol: check_action
; entry_ea: 0x12a0
; source_sha256: 6e90b0a95384f6ced071e1ee1d0aefcc3ccc0ef07074ccf142073d9d07de418f
; chunk: 0x12a0-0x16f4
0x000012a0:  05 00 1c 3c a0 a3 9c 27  li      $gp, (_GLOBAL_OFFSET_TABLE_+0x7FF0 - .)
0x000012a8:  21 e0 99 03              addu    $gp, $t9
0x000012ac:  88 ff bd 27              addiu   $sp, -0x78
0x000012b0:  70 00 bf af              sw      $ra, 0x68+var_s8($sp)
0x000012b4:  6c 00 b1 af              sw      $s1, 0x68+var_s4($sp)
0x000012b8:  68 00 b0 af              sw      $s0, 0x68+var_s0($sp)
0x000012bc:  10 00 bc af              sw      $gp, 0x68+var_58($sp)
0x000012c0:  18 80 82 8f              li      $v0, 0
0x000012c4:  64 80 99 8f              la      $t9, memset
0x000012c8:  20 29 43 90              lbu     $v1, byte_2920($v0)
0x000012cc:  19 00 a4 27              addiu   $a0, $sp, 0x68+var_4F
0x000012d0:  18 00 a3 a3              sb      $v1, 0x68+var_50($sp)
0x000012d4:  21 28 00 00              move    $a1, $zero
0x000012d8:  09 f8 20 03              jalr    $t9  # memset
0x000012dc:  4f 00 06 24              li      $a2, 0x4F  # 'O'
0x000012e0:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000012e4:  18 00 b0 27              addiu   $s0, $sp, 0x68+var_50
0x000012e8:  18 80 84 8f              li      $a0, 0
0x000012ec:  5c 80 99 8f              la      $t9, file_to_buf
0x000012f0:  e4 26 84 24              addiu   $a0, aTmpAction # "/tmp/action"
0x000012f4:  21 28 00 02              move    $a1, $s0
0x000012f8:  09 f8 20 03              jalr    $t9  # file_to_buf
0x000012fc:  50 00 06 24              li      $a2, 0x50  # 'P'
0x00001300:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001304:  07 00 40 14              bnez    $v0, loc_1324
0x00001308:  21 20 00 02              move    $a0, $s0
0x0000130c:  21 10 00 00              move    $v0, $zero
0x00001310:  70 00 bf 8f              lw      $ra, 0x68+var_s8($sp)
0x00001314:  6c 00 b1 8f              lw      $s1, 0x68+var_s4($sp)
0x00001318:  68 00 b0 8f              lw      $s0, 0x68+var_s0($sp)
0x0000131c:  08 00 e0 03              jr      $ra
0x00001320:  78 00 bd 27              addiu   $sp, 0x78
0x00001324:  18 80 85 8f              li      $a1, 0
0x00001328:  58 80 99 8f              la      $t9, strcmp
0x0000132c:  f0 26 a5 24              addiu   $a1, aActTftpUpgrade # "ACT_TFTP_UPGRADE"
0x00001330:  09 f8 20 03              jalr    $t9  # strcmp
0x00001334:  21 88 20 03              move    $s1, $t9
0x00001338:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x0000133c:  1e 00 40 14              bnez    $v0, loc_13B8
0x00001340:  00 00 00 00              nop
0x00001344:  18 80 84 8f              li      $a0, 0
0x00001348:  18 80 85 8f              li      $a1, 0
0x0000134c:  6c 80 99 8f              la      $t9, fopen
0x00001350:  04 27 84 24              addiu   $a0, aDevConsole # "/dev/console"
0x00001354:  09 f8 20 03              jalr    $t9  # fopen
0x00001358:  e0 26 a5 24              addiu   $a1, unk_26E0
0x0000135c:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001360:  0f 00 40 10              beqz    $v0, loc_13A0
0x00001364:  21 80 40 00              move    $s0, $v0
0x00001368:  18 80 84 8f              li      $a0, 0
0x0000136c:  4c 80 99 8f              la      $t9, fwrite
0x00001370:  14 27 84 24              addiu   $a0, aUpgradingFromT # "Upgrading from tftp now ...\n"
0x00001374:  01 00 05 24              li      $a1, 1
0x00001378:  1c 00 06 24              li      $a2, 0x1C
0x0000137c:  09 f8 20 03              jalr    $t9  # fwrite
0x00001380:  21 38 40 00              move    $a3, $v0
0x00001384:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001388:  00 00 00 00              nop
0x0000138c:  60 80 99 8f              la      $t9, fclose
0x00001390:  00 00 00 00              nop
0x00001394:  09 f8 20 03              jalr    $t9  # fclose
0x00001398:  21 20 00 02              move    $a0, $s0
0x0000139c:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000013a0:  70 00 bf 8f              lw      $ra, 0x68+var_s8($sp)
0x000013a4:  6c 00 b1 8f              lw      $s1, 0x68+var_s4($sp)
0x000013a8:  68 00 b0 8f              lw      $s0, 0x68+var_s0($sp)
0x000013ac:  01 00 02 24              li      $v0, 1
0x000013b0:  08 00 e0 03              jr      $ra
0x000013b4:  78 00 bd 27              addiu   $sp, 0x78
0x000013b8:  18 80 85 8f              li      $a1, 0
0x000013bc:  58 80 99 8f              la      $t9, strcmp
0x000013c0:  34 27 a5 24              addiu   $a1, aActWebsUpgrade # "ACT_WEBS_UPGRADE"
0x000013c4:  21 c8 20 02              move    $t9, $s1
0x000013c8:  09 f8 20 03              jalr    $t9  # strcmp
0x000013cc:  21 20 00 02              move    $a0, $s0
0x000013d0:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000013d4:  1e 00 40 14              bnez    $v0, loc_1450
0x000013d8:  00 00 00 00              nop
0x000013dc:  18 80 84 8f              li      $a0, 0
0x000013e0:  18 80 85 8f              li      $a1, 0
0x000013e4:  6c 80 99 8f              la      $t9, fopen
0x000013e8:  04 27 84 24              addiu   $a0, aDevConsole # "/dev/console"
0x000013ec:  09 f8 20 03              jalr    $t9  # fopen
0x000013f0:  e0 26 a5 24              addiu   $a1, unk_26E0
0x000013f4:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000013f8:  0f 00 40 10              beqz    $v0, loc_1438
0x000013fc:  21 80 40 00              move    $s0, $v0
0x00001400:  18 80 84 8f              li      $a0, 0
0x00001404:  4c 80 99 8f              la      $t9, fwrite
0x00001408:  48 27 84 24              addiu   $a0, aUpgradingFromW # "Upgrading from web (https) now ...\n"
0x0000140c:  01 00 05 24              li      $a1, 1
0x00001410:  23 00 06 24              li      $a2, 0x23  # '#'
0x00001414:  09 f8 20 03              jalr    $t9  # fwrite
0x00001418:  21 38 40 00              move    $a3, $v0
0x0000141c:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001420:  00 00 00 00              nop
0x00001424:  60 80 99 8f              la      $t9, fclose
0x00001428:  00 00 00 00              nop
0x0000142c:  09 f8 20 03              jalr    $t9  # fclose
0x00001430:  21 20 00 02              move    $a0, $s0
0x00001434:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001438:  70 00 bf 8f              lw      $ra, 0x68+var_s8($sp)
0x0000143c:  6c 00 b1 8f              lw      $s1, 0x68+var_s4($sp)
0x00001440:  68 00 b0 8f              lw      $s0, 0x68+var_s0($sp)
0x00001444:  03 00 02 24              li      $v0, 3
0x00001448:  08 00 e0 03              jr      $ra
0x0000144c:  78 00 bd 27              addiu   $sp, 0x78
0x00001450:  18 80 85 8f              li      $a1, 0
0x00001454:  58 80 99 8f              la      $t9, strcmp
0x00001458:  6c 27 a5 24              addiu   $a1, aActWebUpgrade # "ACT_WEB_UPGRADE"
0x0000145c:  21 c8 20 02              move    $t9, $s1
0x00001460:  09 f8 20 03              jalr    $t9  # strcmp
0x00001464:  21 20 00 02              move    $a0, $s0
0x00001468:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x0000146c:  1a 00 40 14              bnez    $v0, loc_14D8
0x00001470:  00 00 00 00              nop
0x00001474:  18 80 84 8f              li      $a0, 0
0x00001478:  18 80 85 8f              li      $a1, 0
0x0000147c:  6c 80 99 8f              la      $t9, fopen
0x00001480:  04 27 84 24              addiu   $a0, aDevConsole # "/dev/console"
0x00001484:  09 f8 20 03              jalr    $t9  # fopen
0x00001488:  e0 26 a5 24              addiu   $a1, unk_26E0
0x0000148c:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001490:  0f 00 40 10              beqz    $v0, loc_14D0
0x00001494:  21 80 40 00              move    $s0, $v0
0x00001498:  18 80 84 8f              li      $a0, 0
0x0000149c:  4c 80 99 8f              la      $t9, fwrite
0x000014a0:  7c 27 84 24              addiu   $a0, aUpgradingFromW_0 # "Upgrading from web (http) now ...\n"
0x000014a4:  01 00 05 24              li      $a1, 1
0x000014a8:  22 00 06 24              li      $a2, 0x22  # '"'
0x000014ac:  09 f8 20 03              jalr    $t9  # fwrite
0x000014b0:  21 38 40 00              move    $a3, $v0
0x000014b4:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000014b8:  00 00 00 00              nop
0x000014bc:  60 80 99 8f              la      $t9, fclose
0x000014c0:  00 00 00 00              nop
0x000014c4:  09 f8 20 03              jalr    $t9  # fclose
0x000014c8:  21 20 00 02              move    $a0, $s0
0x000014cc:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000014d0:  8f ff 00 10              b       loc_1310
0x000014d4:  02 00 02 24              li      $v0, 2
0x000014d8:  18 80 85 8f              li      $a1, 0
0x000014dc:  58 80 99 8f              la      $t9, strcmp
0x000014e0:  a0 27 a5 24              addiu   $a1, aActSwRestore # "ACT_SW_RESTORE"
0x000014e4:  21 c8 20 02              move    $t9, $s1
0x000014e8:  09 f8 20 03              jalr    $t9  # strcmp
0x000014ec:  21 20 00 02              move    $a0, $s0
0x000014f0:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000014f4:  1a 00 40 14              bnez    $v0, loc_1560
0x000014f8:  00 00 00 00              nop
0x000014fc:  18 80 84 8f              li      $a0, 0
0x00001500:  18 80 85 8f              li      $a1, 0
0x00001504:  6c 80 99 8f              la      $t9, fopen
0x00001508:  04 27 84 24              addiu   $a0, aDevConsole # "/dev/console"
0x0000150c:  09 f8 20 03              jalr    $t9  # fopen
0x00001510:  e0 26 a5 24              addiu   $a1, unk_26E0
0x00001514:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001518:  0f 00 40 10              beqz    $v0, loc_1558
0x0000151c:  21 80 40 00              move    $s0, $v0
0x00001520:  18 80 84 8f              li      $a0, 0
0x00001524:  4c 80 99 8f              la      $t9, fwrite
0x00001528:  b0 27 84 24              addiu   $a0, aReceivingResto # "Receiving restore command from web ..."...
0x0000152c:  01 00 05 24              li      $a1, 1
0x00001530:  27 00 06 24              li      $a2, 0x27  # '''
0x00001534:  09 f8 20 03              jalr    $t9  # fwrite
0x00001538:  21 38 40 00              move    $a3, $v0
0x0000153c:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001540:  00 00 00 00              nop
0x00001544:  60 80 99 8f              la      $t9, fclose
0x00001548:  00 00 00 00              nop
0x0000154c:  09 f8 20 03              jalr    $t9  # fclose
0x00001550:  21 20 00 02              move    $a0, $s0
0x00001554:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001558:  6d ff 00 10              b       loc_1310
0x0000155c:  04 00 02 24              li      $v0, 4
0x00001560:  18 80 85 8f              li      $a1, 0
0x00001564:  58 80 99 8f              la      $t9, strcmp
0x00001568:  d8 27 a5 24              addiu   $a1, aActHwRestore # "ACT_HW_RESTORE"
0x0000156c:  21 c8 20 02              move    $t9, $s1
0x00001570:  09 f8 20 03              jalr    $t9  # strcmp
0x00001574:  21 20 00 02              move    $a0, $s0
0x00001578:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x0000157c:  1a 00 40 14              bnez    $v0, loc_15E8
0x00001580:  00 00 00 00              nop
0x00001584:  18 80 84 8f              li      $a0, 0
0x00001588:  18 80 85 8f              li      $a1, 0
0x0000158c:  6c 80 99 8f              la      $t9, fopen
0x00001590:  04 27 84 24              addiu   $a0, aDevConsole # "/dev/console"
0x00001594:  09 f8 20 03              jalr    $t9  # fopen
0x00001598:  e0 26 a5 24              addiu   $a1, unk_26E0
0x0000159c:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000015a0:  0f 00 40 10              beqz    $v0, loc_15E0
0x000015a4:  21 80 40 00              move    $s0, $v0
0x000015a8:  18 80 84 8f              li      $a0, 0
0x000015ac:  4c 80 99 8f              la      $t9, fwrite
0x000015b0:  e8 27 84 24              addiu   $a0, aReceivingResto_0 # "Receiving restore commond from resetbut"...
0x000015b4:  01 00 05 24              li      $a1, 1
0x000015b8:  2f 00 06 24              li      $a2, 0x2F  # '/'
0x000015bc:  09 f8 20 03              jalr    $t9  # fwrite
0x000015c0:  21 38 40 00              move    $a3, $v0
0x000015c4:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000015c8:  00 00 00 00              nop
0x000015cc:  60 80 99 8f              la      $t9, fclose
0x000015d0:  00 00 00 00              nop
0x000015d4:  09 f8 20 03              jalr    $t9  # fclose
0x000015d8:  21 20 00 02              move    $a0, $s0
0x000015dc:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000015e0:  4b ff 00 10              b       loc_1310
0x000015e4:  05 00 02 24              li      $v0, 5
0x000015e8:  18 80 85 8f              li      $a1, 0
0x000015ec:  58 80 99 8f              la      $t9, strcmp
0x000015f0:  18 28 a5 24              addiu   $a1, aActNvramCommit # "ACT_NVRAM_COMMIT"
0x000015f4:  21 c8 20 02              move    $t9, $s1
0x000015f8:  09 f8 20 03              jalr    $t9  # strcmp
0x000015fc:  21 20 00 02              move    $a0, $s0
0x00001600:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001604:  1a 00 40 14              bnez    $v0, loc_1670
0x00001608:  21 20 00 02              move    $a0, $s0
0x0000160c:  18 80 84 8f              li      $a0, 0
0x00001610:  18 80 85 8f              li      $a1, 0
0x00001614:  6c 80 99 8f              la      $t9, fopen
0x00001618:  04 27 84 24              addiu   $a0, aDevConsole # "/dev/console"
0x0000161c:  09 f8 20 03              jalr    $t9  # fopen
0x00001620:  e0 26 a5 24              addiu   $a1, unk_26E0
0x00001624:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001628:  0f 00 40 10              beqz    $v0, loc_1668
0x0000162c:  21 80 40 00              move    $s0, $v0
0x00001630:  18 80 84 8f              li      $a0, 0
0x00001634:  4c 80 99 8f              la      $t9, fwrite
0x00001638:  2c 28 84 24              addiu   $a0, aCommittingNvra # "Committing nvram now ...\n"
0x0000163c:  01 00 05 24              li      $a1, 1
0x00001640:  19 00 06 24              li      $a2, 0x19
0x00001644:  09 f8 20 03              jalr    $t9  # fwrite
0x00001648:  21 38 40 00              move    $a3, $v0
0x0000164c:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001650:  00 00 00 00              nop
0x00001654:  60 80 99 8f              la      $t9, fclose
0x00001658:  00 00 00 00              nop
0x0000165c:  09 f8 20 03              jalr    $t9  # fclose
0x00001660:  21 20 00 02              move    $a0, $s0
0x00001664:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001668:  29 ff 00 10              b       loc_1310
0x0000166c:  07 00 02 24              li      $v0, 7
0x00001670:  18 80 85 8f              li      $a1, 0
0x00001674:  58 80 99 8f              la      $t9, strcmp
0x00001678:  21 c8 20 02              move    $t9, $s1
0x0000167c:  09 f8 20 03              jalr    $t9  # strcmp
0x00001680:  48 28 a5 24              addiu   $a1, aActEraseNvram # "ACT_ERASE_NVRAM"
0x00001684:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x00001688:  21 ff 40 14              bnez    $v0, loc_1310
0x0000168c:  21 10 00 00              move    $v0, $zero
0x00001690:  18 80 84 8f              li      $a0, 0
0x00001694:  18 80 85 8f              li      $a1, 0
0x00001698:  6c 80 99 8f              la      $t9, fopen
0x0000169c:  04 27 84 24              addiu   $a0, aDevConsole # "/dev/console"
0x000016a0:  09 f8 20 03              jalr    $t9  # fopen
0x000016a4:  e0 26 a5 24              addiu   $a1, unk_26E0
0x000016a8:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000016ac:  0f 00 40 10              beqz    $v0, loc_16EC
0x000016b0:  21 80 40 00              move    $s0, $v0
0x000016b4:  18 80 84 8f              li      $a0, 0
0x000016b8:  4c 80 99 8f              la      $t9, fwrite
0x000016bc:  58 28 84 24              addiu   $a0, aErasingNvramNo # "Erasing nvram now ...\n"
0x000016c0:  01 00 05 24              li      $a1, 1
0x000016c4:  16 00 06 24              li      $a2, 0x16
0x000016c8:  09 f8 20 03              jalr    $t9  # fwrite
0x000016cc:  21 38 40 00              move    $a3, $v0
0x000016d0:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000016d4:  00 00 00 00              nop
0x000016d8:  60 80 99 8f              la      $t9, fclose
0x000016dc:  00 00 00 00              nop
0x000016e0:  09 f8 20 03              jalr    $t9  # fclose
0x000016e4:  21 20 00 02              move    $a0, $s0
0x000016e8:  10 00 bc 8f              lw      $gp, 0x68+var_58($sp)
0x000016ec:  08 ff 00 10              b       loc_1310
0x000016f0:  06 00 02 24              li      $v0, 6
