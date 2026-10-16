int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *v5; // $v0
  int v6; // $s3
  int v7; // $s2
  FILE *v8; // $v0
  FILE *v9; // $s0
  int result; // $v0
  int v11; // $s0
  int i; // $a0
  int v13; // $v1
  int v14; // $s2
  int v15; // $s1
  const char **v16; // $s0
  const char *v17; // $a1
  const char **v18; // $s0
  const char *v19; // $s3
  char *v20; // $s1
  int v21; // $a0
  int v22; // $s2
  int v23; // $s0
  const char *v24; // $s0
  char dest[256]; // [sp+30h] [-180h] BYREF
  char name[64]; // [sp+130h] [-80h] BYREF
  int v27; // [sp+170h] [-40h] BYREF
  time_t timer; // [sp+174h] [-3Ch] BYREF
  int v29; // [sp+178h] [-38h] BYREF
  int v30; // [sp+17Ch] [-34h]
  int v31; // [sp+180h] [-30h]
  int v32; // [sp+184h] [-2Ch]
  int v33; // [sp+188h] [-28h]
  int v34; // [sp+18Ch] [-24h]
  int v35; // [sp+190h] [-20h]
  int v36; // [sp+194h] [-1Ch]
  int v37; // [sp+198h] [-18h]
  int v38; // [sp+19Ch] [-14h]
  int v39; // [sp+1A0h] [-10h]
  int v40; // [sp+1A4h] [-Ch]
  struct addrinfo *req; // [sp+1A8h] [-8h]
  struct addrinfo **pai; // [sp+1ACh] [-4h]

  memset(dest, 0, sizeof(dest));
  memset(name, 0, sizeof(name));
  v5 = (const char *)nvram_get((int)"wan_mac");
  if ( !v5 )
    v5 = "";
  v6 = atoi(v5);
  v7 = 0;
  if ( !fopen("/tmp/ntp_firstboot", "r") )
  {
    fwrite("File /tmp/ntp_firstboot not exist!, First boot!!\n", 1u, 0x31u, GVar_stderr);
    v8 = fopen("/tmp/ntp_firstboot", "w");
    v9 = v8;
    if ( !v8 )
    {
      fwrite("Open file /tmp/ntp_firstboot failed.\n", 1u, 0x25u, GVar_stderr);
      return -1;
    }
    fwrite("first booted!\n", 1u, 0xEu, v8);
    fclose(v9);
    v7 = 1;
  }
  v11 = open("/var/lock/ntpclient", 769);
  if ( v11 == -1 )
  {
    fwrite("Create /var/lock/ntpclient file FAIL.", 1u, 0x25u, GVar_stderr);
    return -1;
  }
  if ( lockf(v11, 2, 0) == -1 )
  {
    if ( close(v11) == -1 )
      fwrite("Close /var/lock/ntpclient file FAIL.", 1u, 0x24u, GVar_stderr);
    return -1;
  }
  else
  {
    if ( v7 )
    {
      time(&timer);
      srandom(v6 + timer);
      random();
    }
    v37 = 0;
    v40 = 0;
    v39 = 3;
    v38 = 0;
LABEL_16:
    for ( i = argc; ; i = argc )
    {
      v13 = getopt(i, (char *const *)argv, "c:dh:i:p:lrs");
      if ( v13 == -1 )
        break;
      switch ( v13 )
      {
        case 'c':
          v38 = atoi(GVar_optarg);
          goto LABEL_16;
        case 'd':
          ++GVar_debug;
          goto LABEL_16;
        case 'h':
          v14 = 0;
          if ( argc <= 0 )
          {
            v15 = 1;
            goto LABEL_27;
          }
          v16 = argv;
          break;
        case 'i':
          v39 = atoi(GVar_optarg);
          goto LABEL_16;
        case 'l':
          ++GVar_live;
          goto LABEL_16;
        case 'p':
          v40 = (short)atoi(GVar_optarg);
          goto LABEL_16;
        case 'r':
          ++v37;
          goto LABEL_16;
        case 's':
          GVar_set_clock = 1;
          v38 = 1;
          goto LABEL_16;
        default:
          usage(*argv);
          exit(1);
          return result;
      }
      while ( 1 )
      {
        v15 = v14 + 1;
        if ( !strcmp(*v16, "-h") )
          break;
        ++v14;
        ++v16;
        if ( v14 == argc )
        {
          v15 = v14 + 1;
          break;
        }
      }
LABEL_27:
      if ( v15 >= argc )
        goto LABEL_16;
      v17 = argv[v15];
      if ( *v17 == 45 )
        goto LABEL_16;
      v18 = &argv[v14];
      while ( 1 )
      {
        strncat(dest, v17, 0x100u);
        strcat(dest, " ");
        if ( ++v15 >= argc )
          break;
        v17 = v18[2];
        ++v18;
        if ( *v17 == 45 )
          goto LABEL_16;
      }
    }
    if ( v37 )
    {
      do_replay();
      exit(0);
    }
    if ( GVar_debug )
    {
      fprintf(
        GVar_stderr,
        "Configuration:\n"
        "  -c probe_count %d\n"
        "  -d (GVar_debug)     %d\n"
        "  -h hostname    %s\n"
        "  -i interval    %d\n"
        "  -l GVar_live        %d\n"
        "  -p local_port  %d\n"
        "  -s GVar_set_clock   %d\n",
        v38,
        GVar_debug,
        dest,
        v39,
        GVar_live,
        v40,
        GVar_set_clock);
      fflush(GVar_stderr);
    }
    GVar_bkf_start = time(0);
    GVar_bkf_current = time(0);
    GVar_bkf_interval = 60;
    v33 = 0;
    v34 = 0;
    v35 = 0;
    v36 = 0;
    v30 = 2;
    v31 = 1;
    v29 = 0;
    v32 = 0;
    v19 = &dest[strspn(dest, " ")];
    strncpy(name, v19, 0x40u);
    dest[strcspn(name, " ") + 256] = 0;
    name[63] = 0;
    v20 = strchr(v19, 32);
    if ( name[0] )
    {
      req = (struct addrinfo *)&v29;
      pai = (struct addrinfo **)&v27;
      do
      {
        if ( !strcmp(name, "6") )
        {
          v33 = 0;
          v34 = 0;
          v35 = 0;
          v36 = 0;
          v30 = 10;
          v31 = 1;
          v29 = 0;
          v32 = 0;
        }
        else if ( !strcmp(name, "4") )
        {
          v33 = 0;
          v34 = 0;
          v35 = 0;
          v36 = 0;
          v30 = 2;
          v31 = 1;
          v29 = 0;
          v32 = 0;
        }
        else
        {
          if ( getaddrinfo(name, 0, req, pai) )
            exit(1);
          v21 = *(unsigned int *)(v27 + 4);
          v22 = 4;
          if ( v21 != 2 )
            v22 = 6;
          v23 = socket(v21, 1, 17);
          if ( v23 == -1 )
          {
            perror("socket");
            exit(1);
          }
          setup_receive(v23, 0, v40, v22);
          if ( !setup_transmit(v23, name, 0x7Bu, v22) && !primary_loop(v23, v38, v39) )
          {
            close(v23);
            return 0;
          }
          close(v23);
        }
        if ( v20 )
          v24 = &v20[strspn(v20, " ")];
        else
          v24 = "";
        strncpy(name, v24, 0x40u);
        dest[strcspn(name, " ") + 256] = 0;
        name[63] = 0;
        v20 = strchr(v24, 32);
      }
      while ( name[0] );
    }
    return 1;
  }
}