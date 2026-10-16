int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *v3; // $s0
  int *v4; // $s2
  char *v5; // $v0
  const char *v6; // $a1
  char *v7; // $v0
  const char *v9; // $a0
  char *i; // $s0
  char *v11; // [sp+18h] [-F008h] BYREF
  char dest[61444]; // [sp+1Ch] [-F004h] BYREF

  v3 = argv[1];
  v4 = (int *)(argv + 1);
  if ( !v3 )
    usage();
  do
  {
    while ( 1 )
    {
      if ( !strcmp(v3, "get") )
      {
        if ( *++v4 )
        {
          v5 = (char *)nvram_get(*v4);
          v11 = v5;
          if ( v5 )
            puts(v5);
        }
        goto LABEL_6;
      }
      if ( !strcmp(v3, "set") )
        break;
      if ( !strcmp(v3, "unset") )
      {
        v9 = (const char *)*++v4;
        if ( *v4 )
        {
          ++v4;
          nvram_unset(v9);
          goto LABEL_7;
        }
      }
      else
      {
        if ( !strcmp(v3, "commit") )
        {
          ++v4;
          nvram_commit();
          goto LABEL_7;
        }
        if ( strcmp(v3, "show") && strcmp(v3, "dump") )
          usage();
        nvram_getall((unsigned char *)dest, 61440);
        for ( i = dest; *i; i += strlen(i) + 1 )
          puts(i);
        if ( *(unsigned char *)*v4 != 100 )
        {
          fprintf(GVar_stderr, "size: %d bytes (%d left)\n", &i[20 - (unsigned int)dest], 61440 - (unsigned int)&i[20 - (unsigned int)dest]);
          ++v4;
          goto LABEL_7;
        }
      }
LABEL_6:
      ++v4;
LABEL_7:
      v3 = (const char *)*v4;
      if ( !*v4 )
        return 0;
    }
    v6 = (const char *)*++v4;
    if ( !*v4 )
      goto LABEL_6;
    v11 = dest;
    strncpy(dest, v6, 0xF000u);
    v7 = strsep(&v11, "=");
    ++v4;
    nvram_set(v7, v11);
    v3 = (const char *)*v4;
  }
  while ( *v4 );
  return 0;
}