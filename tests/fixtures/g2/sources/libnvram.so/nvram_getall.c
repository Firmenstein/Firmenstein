int __fastcall nvram_getall(unsigned char *a1, int a2)
{
  int v4; // $s0
  int result; // $v0
  int v6; // $s1

  v4 = nvram_init();
  if ( v4 || !a2 )
    return v4;
  *a1 = 0;
  v6 = read(GVar_fdata, a1, a2);
  if ( v6 < 0 )
    perror("/dev/nvram");
  result = v6;
  if ( a2 == v6 )
    return v4;
  return result;
}