int __fastcall nvram_get(int a1)
{
  int v2; // $a2
  unsigned int v3; // $s0
  unsigned char *v4; // $s1
  int v5; // $s0
  int result; // $v0
  unsigned char v7[104]; // [sp+18h] [-68h] BYREF

  v3 = strlen(a1) + 1;
  if ( nvram_init() )
    return 0;
  if ( v3 >= 0x65 )
  {
    v4 = (unsigned char *)malloc(v3);
    if ( v4 )
      goto LABEL_4;
    return 0;
  }
  v4 = v7;
LABEL_4:
  strcpy(v4, a1, v2);
  if ( read(GVar_fdata, v4, v3) == 4 )
    v5 = *(unsigned int *)v4 + GVar_dword_436F0;
  else
    v5 = 0;
  result = v5;
  if ( v4 != v7 )
  {
    free(v4);
    return v5;
  }
  return result;
}