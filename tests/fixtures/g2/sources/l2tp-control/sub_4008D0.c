int __fastcall sub_4008D0(unsigned char *a1)
{
  int fd; // [sp+18h] [+18h]
  struct sockaddr s; // [sp+1Ch] [+1Ch] BYREF
  struct iovec iovec; // [sp+8Ch] [+8Ch] BYREF
  const char *v5; // [sp+94h] [+94h]
  int v6; // [sp+98h] [+98h]

  if ( *a1 )
  {
    memset(&s, 0, 0x6Eu);
    s.sa_family = 1;
    strncpy(s.sa_data, "/var/run/l2tpctrl", 0x6Bu);
    fd = socket(1, 2, 0);
    if ( fd >= 0 )
    {
      if ( connect(fd, &s, 0x6Eu) >= 0 )
      {
        iovec.iov_base = a1;
        iovec.iov_len = strlen(a1);
        v5 = "\n";
        v6 = 1;
        writev(fd, &iovec, 2);
        return fd;
      }
      else
      {
        perror("connect");
        close(fd);
        return -1;
      }
    }
    else
    {
      perror("socket");
      return -1;
    }
  }
  else
  {
    *_errno_location() = 29;
    return -1;
  }
}