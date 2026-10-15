This is how some of the files were created. If you add something new,
please 
```bash
$ ssh-keygen -t ed25519 -f ca_key -N "" -C test-ca-key
$ ssh-keygen -t ed25519 -f cert_key -N "" -C test-cert-key
$ ssh-keygen -s ca_key -I identity -n principal -V 20250701Z:20250801Z cert_key.pub
$ mv cert_key-cert.pub cert.pub
$ ssh-keygen -s ca_key -I identity -n principal1,principal3 -V 20250701Z:20250801Z cert_key.pub
$ mv cert_key-cert.pub cert_principal_1_3.pub
$ ssh-keygen -s ca_key -I identity -n principal2,principal4 -V 20250701Z:20250801Z cert_key.pub
$ mv cert_key-cert.pub cert_principal_2_4.pub
$ echo "cert-authority $(cat ca_key.pub)" > ca_key_prefix.pub
$ echo "cert-authority,principals=\"principal1,principal2\" $(cat ca_key.pub)" > ca_key_principals.pub
```

cert_unknown_critical.pub is copied from 
https://github.com/openssh/openssh-portable/blob/d1c6c67a50fc957010fa027c6ab970424e9b9142/regress/unittests/authopt/testdata/unknown_critical.cert