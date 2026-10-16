int __fastcall setup_receive(int fd, unsigned int a2, unsigned short a3, int a4)
{
  int v5; // $s0
  struct sockaddr addr; // [sp+18h] [-30h] BYREF
  struct sockaddr v8; // [sp+28h] [-20h] BYREF

  v5 = (short)a3;
  memset(&addr, 0, sizeof(addr));
  if ( a4 == 4 )
  {
    addr.sa_family = 2;
    *(unsigned int *)&addr.sa_data[2] = (a2 >> 8) & 0xFF00 | HIBYTE(a2) | ((a2 & 0xFF00) << 8) | (a2 << 24);
    *(unsigned short *)addr.sa_data = ((unsigned char)a3 << 8) | HIBYTE(a3);
    if ( bind(fd, &addr, 0x10u) == -1 )
    {
      fprintf(GVar_stderr, "could not bind to udp port %d\n", v5);
      perror("bind");
      exit(1);
    }
  }
  else
  {
    v8.sa_family = 10;
    inet_pton(10, "::", &v8.sa_data[6]);
    *(unsigned short *)v8.sa_data = ((unsigned char)v5 << 8) | BYTE1(v5);
    if ( bind(fd, &v8, 0x1Cu) == -1 )
    {
      fprintf(GVar_stderr, "could not bind to udp port %d\n", v5);
      perror("bind");
      exit(1);
    }
  }
  return listen(fd, 3);
}