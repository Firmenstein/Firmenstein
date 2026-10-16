int nvram_commit()
{
  int v0; // $s1
  int v1; // $v0
  int v2; // $s1
  int v3; // $v0
  int v4; // $s0
  int v6; // $v0
  int v7; // $v0
  int v8; // $s0

  v0 = fopen("/dev/console", &GVar_unk_26E0);
  if ( v0 )
  {
    v1 = getpid();
    fprintf(v0, "%d nvram_commit(): start\n", v1);
    fclose(v0);
  }
  if ( check_action() == 6 )
  {
    v7 = fopen("/dev/console", &GVar_unk_26E0);
    v8 = v7;
    if ( v7 )
    {
      fwrite("Waiting 2 seconds...\n", 1, 21, v7);
      fclose(v8);
    }
    sleep(1);
    sleep(1);
  }
  if ( !check_action() || check_action() == 4 || check_action() == 5 || check_action() == 7 )
  {
    buf_to_file((int)"/tmp/action", (int)"ACT_NVRAM_COMMIT");
    v4 = nvram_init();
    if ( !v4 )
    {
      v4 = ioctl(GVar_fdata, 1213418566, 0);
      if ( v4 < 0 )
        perror("/dev/nvram");
      buf_to_file((int)"/tmp/action", (int)"ACT_IDLE");
      v2 = fopen("/dev/console", &GVar_unk_26E0);
      if ( v2 )
      {
        v6 = getpid();
        fprintf(v2, "%d nvram_commit(): end\n", v6);
        goto LABEL_16;
      }
    }
    return v4;
  }
  v2 = fopen("/dev/console", &GVar_unk_26E0);
  if ( !v2 )
    return 0;
  v4 = 0;
  v3 = getpid();
  fprintf(v2, "%d nvram_commit():  nothing to do...\n", v3);
LABEL_16:
  fclose(v2);
  return v4;
}