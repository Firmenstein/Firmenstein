int __fastcall sub_1B5C(const char *a1, const char *a2)
{
  int result; // $v0
  int v5; // $s0
  unsigned int v6; // $s2
  unsigned char *v7; // $s1
  int v8; // $s0
  unsigned char v9[104]; // [sp+18h] [-68h] BYREF

  v5 = ((int (*)(void))strlen)();
  result = nvram_init();
  if ( result )
    return result;
  v6 = v5 + 1;
  if ( a2 )
    v6 += strlen(a2) + 1;
  v7 = v9;
  if ( v6 >= 0x65 )
  {
    v7 = (unsigned char *)malloc(v6);
    if ( !v7 )
      return -12;
  }
  if ( a2 )
    sprintf(v7, "%s=%s", a1, a2);
  else
    strcpy(v7, a1, a1);
  v8 = write(GVar_fdata, v7, v6);
  if ( v8 < 0 )
  {
    perror("/dev/nvram");
    if ( v9 == v7 )
      goto LABEL_10;
    goto LABEL_9;
  }
  if ( v9 != v7 )
LABEL_9:
    free(v7);
LABEL_10:
  if ( v8 == v6 )
    return 0;
  return v8;
}