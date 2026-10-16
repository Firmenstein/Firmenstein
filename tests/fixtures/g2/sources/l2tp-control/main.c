int __fastcall main(int argc, const char **argv, const char **envp)
{
  ssize_t n; // [sp+18h] [+18h]
  int fd; // [sp+1Ch] [+1Ch]
  unsigned char buf[4096]; // [sp+20h] [+20h] BYREF

  if ( argc == 2 )
  {
    fd = sub_4008D0(argv[1]);
    if ( fd >= 0 )
    {
      while ( 1 )
      {
        n = read(fd, buf, 0x1000u);
        if ( n < 0 )
        {
          perror("read");
          putchar(10);
          close(fd);
          return 1;
        }
        if ( !n )
          break;
        write(1, buf, n);
      }
      putchar(10);
      close(fd);
      return 0;
    }
    else
    {
      return 1;
    }
  }
  else
  {
    fprintf(GVar_stderr, "Usage: %s command\n", *argv);
    return 1;
  }
}