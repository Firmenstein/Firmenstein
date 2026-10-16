int __fastcall file_to_buf(int a1, int a2, int a3)
{
  int v6; // $v0
  int v7; // $s0

  memset(a2, 0);
  v6 = fopen(a1, "r");
  v7 = v6;
  if ( !v6 )
    return 0;
  fgets(a2, a3, v6);
  fclose(v7);
  return 1;
}