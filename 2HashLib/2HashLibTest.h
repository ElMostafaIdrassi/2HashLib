#ifndef HASHLIBTEST_H
#define HASHLIBLIBTEST_H

/*  ====================================================================
Makes sure all the functions provided by the library are working as expected
*	MD5 : Based on RFC 1321 ; No NIST based test vector available
*	SHA1, SHA2 : Based on FIPS 180-4 NIST test vectors (byte-oriented) : http://csrc.nist.gov/groups/STM/cavp/secure-hashing.html
*/
int md5Test();
int sha1Test();
int sha256Test();
int sha384Test();
int sha512Test();

#endif // !HASHLIBTEST_H