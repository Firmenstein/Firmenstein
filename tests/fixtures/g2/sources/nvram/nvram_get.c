// attributes: thunk
int __fastcall nvram_get(int a1)
{
  const char *v1; // $a0

  MEMORY[0](a1);
  return nvram_unset(v1);
}