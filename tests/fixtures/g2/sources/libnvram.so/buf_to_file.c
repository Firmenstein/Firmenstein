// Alternative name is '_ftext'
int __fastcall buf_to_file(int a1, int a2)
{
  int v3; // $v0
  int v4; // $s0

  v3 = fopen(a1, &GVar_unk_26E0);
  v4 = v3;
  if ( !v3 )
    return 0;
  fputs(a2, v3);
  fclose(v4);
  return 1;
}