int __fastcall stuff_net_addr(unsigned int *a1, const char *a2)
{
  struct hostent *v4; // $v0
  int h_length; // $a2

  v4 = gethostbyname(a2);
  if ( v4 )
  {
    h_length = v4->h_length;
    if ( h_length == 4 )
    {
      *a1 = **(unsigned int **)v4->h_addr_list;
      return 0;
    }
    else
    {
      fprintf(GVar_stderr, "oops %d\n", h_length);
      return 1;
    }
  }
  else
  {
    herror(a2);
    return 1;
  }
}