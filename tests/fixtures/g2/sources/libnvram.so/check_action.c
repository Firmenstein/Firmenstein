int check_action()
{
  int result; // $v0
  int v1; // $v0
  int v2; // $s0
  int v3; // $v0
  int v4; // $s0
  int v5; // $v0
  int v6; // $s0
  int v7; // $v0
  int v8; // $s0
  int v9; // $v0
  int v10; // $s0
  int v11; // $v0
  int v12; // $s0
  bool v13; // dc
  int v14; // $v0
  int v15; // $s0
  char v16; // [sp+18h] [-50h] BYREF
  unsigned char v17[79]; // [sp+19h] [-4Fh] BYREF

  v16 = 0;
  memset(v17, 0);
  if ( !file_to_buf((int)"/tmp/action", (int)&v16, 80) )
    return 0;
  if ( !strcmp(&v16, "ACT_TFTP_UPGRADE") )
  {
    v1 = fopen("/dev/console", &GVar_unk_26E0);
    v2 = v1;
    if ( v1 )
    {
      fwrite("Upgrading from tftp now ...\n", 1, 28, v1);
      fclose(v2);
    }
    return 1;
  }
  else if ( !strcmp(&v16, "ACT_WEBS_UPGRADE") )
  {
    v3 = fopen("/dev/console", &GVar_unk_26E0);
    v4 = v3;
    if ( v3 )
    {
      fwrite("Upgrading from web (https) now ...\n", 1, 35, v3);
      fclose(v4);
    }
    return 3;
  }
  else if ( !strcmp(&v16, "ACT_WEB_UPGRADE") )
  {
    v5 = fopen("/dev/console", &GVar_unk_26E0);
    v6 = v5;
    if ( v5 )
    {
      fwrite("Upgrading from web (http) now ...\n", 1, 34, v5);
      fclose(v6);
    }
    return 2;
  }
  else if ( !strcmp(&v16, "ACT_SW_RESTORE") )
  {
    v7 = fopen("/dev/console", &GVar_unk_26E0);
    v8 = v7;
    if ( v7 )
    {
      fwrite("Receiving restore command from web ...\n", 1, 39, v7);
      fclose(v8);
    }
    return 4;
  }
  else if ( !strcmp(&v16, "ACT_HW_RESTORE") )
  {
    v9 = fopen("/dev/console", &GVar_unk_26E0);
    v10 = v9;
    if ( v9 )
    {
      fwrite("Receiving restore commond from resetbutton ...\n", 1, 47, v9);
      fclose(v10);
    }
    return 5;
  }
  else if ( !strcmp(&v16, "ACT_NVRAM_COMMIT") )
  {
    v11 = fopen("/dev/console", &GVar_unk_26E0);
    v12 = v11;
    if ( v11 )
    {
      fwrite("Committing nvram now ...\n", 1, 25, v11);
      fclose(v12);
    }
    return 7;
  }
  else
  {
    v13 = strcmp(&v16, "ACT_ERASE_NVRAM") != 0;
    result = 0;
    if ( !v13 )
    {
      v14 = fopen("/dev/console", &GVar_unk_26E0);
      v15 = v14;
      if ( v14 )
      {
        fwrite("Erasing nvram now ...\n", 1, 22, v14);
        fclose(v15);
      }
      return 6;
    }
  }
  return result;
}