int __fastcall setup_transmit(int fd, const char *a2, unsigned short a3, int a4)
{
  bool v6; // dc
  int result; // $v0
  struct sockaddr addr; // [sp+18h] [-30h] BYREF
  struct sockaddr v9; // [sp+28h] [-20h] BYREF
  int v10; // [sp+38h] [-10h]
  int v11; // [sp+3Ch] [-Ch]
  int v12; // [sp+40h] [-8h]

  memset(&addr, 0, sizeof(addr));
  memset(&v9, 0, sizeof(v9));
  v10 = 0;
  v11 = 0;
  v12 = 0;
  if ( a4 == 4 )
  {
    addr.sa_family = 2;
    v6 = stuff_net_addr(&addr.sa_data[2], a2) != 0;
    result = 1;
    if ( v6 )
      return result;
    *(unsigned short *)addr.sa_data = ((unsigned char)a3 << 8) | HIBYTE(a3);
    if ( connect(fd, &addr, 0x10u) == -1 )
    {
      perror("(ntpclient) connect");
      return 1;
    }
  }
  else
  {
    v9.sa_family = 10;
    v6 = stuff_net_addr6(&v9.sa_data[6], a2) != 0;
    result = 1;
    if ( v6 )
      return result;
    *(unsigned short *)v9.sa_data = ((unsigned char)a3 << 8) | HIBYTE(a3);
    if ( connect(fd, &v9, 0x1Cu) == -1 )
    {
      perror("(ntpclient) connect");
      return 1;
    }
  }
  return 0;
}