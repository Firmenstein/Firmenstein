int __fastcall stuff_net_addr6(unsigned int *a1, const char *a2)
{
  struct hostent *v4; // $v0
  char *v6; // $v0
  int v7; // $a1
  int v8; // $a0
  int v9; // $v1

  v4 = gethostbyname2(a2, 10);
  if ( v4 )
  {
    v6 = *v4->h_addr_list;
    v7 = *((unsigned int *)v6 + 1);
    v8 = *((unsigned int *)v6 + 2);
    v9 = *((unsigned int *)v6 + 3);
    *a1 = *(unsigned int *)v6;
    a1[1] = v7;
    a1[2] = v8;
    a1[3] = v9;
    return 0;
  }
  else
  {
    herror(a2);
    return 1;
  }
}