// attributes: thunk
int __fastcall nvram_unset(const char *a1)
{
  MEMORY[0](a1);
  return nvram_commit();
}