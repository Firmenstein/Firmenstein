// attributes: thunk
char *__fastcall nvram_set(const char *a1, const char *a2)
{
  char *v2; // $a0
  const char *v3; // $a1
  size_t v4; // $a2

  MEMORY[0](a1, a2);
  return strncpy(v2, v3, v4);
}