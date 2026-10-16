int nvram_init()
{
  int v1; // $v0

  if ( GVar_fdata >= 0 )
    return 0;
  v1 = open("/dev/nvram", 2);
  GVar_fdata = v1;
  if ( v1 >= 0 )
  {
    GVar_dword_436F0 = mmap(0, 61440, 1, 1, v1, 0);
    if ( GVar_dword_436F0 != -1 )
      return 0;
    close(GVar_fdata);
    GVar_fdata = -1;
  }
  perror("/dev/nvram");
  return *(unsigned int *)_errno_location();
}