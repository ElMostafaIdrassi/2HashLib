/*
* Copyright 2018 El Mostafa IDRASSI <mostafa.idrassi@tutanota.com>.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef HASHLIBTEST_H
#define HASHLIBLIBTEST_H

/*  ====================================================================
 *  Make sure all the functions provided by the library are working as expected
 *		MD5 : Based on RFC 1321 ; No NIST based test vector available
 *		SHA1, SHA2 : Based on FIPS 180-4 NIST test vectors (byte-oriented) : http://csrc.nist.gov/groups/STM/cavp/secure-hashing.html
 */
int md5Test();
int sha1Test();
int sha256Test();
int sha384Test();
int sha512Test();

#endif // !HASHLIBTEST_H