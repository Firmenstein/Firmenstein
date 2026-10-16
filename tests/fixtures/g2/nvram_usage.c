void  usage()
{
  fwrite("usage: nvram [get name] [set name=value] [unset name] [show] [commit] ...\n", 1u, 0x4Au, GVar_stderr);
  exit(0);
}