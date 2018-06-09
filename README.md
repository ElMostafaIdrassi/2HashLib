# 2HashLib
A small C++ library that provides a high-level API to perform hash operations

It is based on the OpenSSL 1.1.0h hash implementation, yet it doesn't rely on the OpenSSL EVP.

It currently supports MD5 (for legacy use), SHA1, SHA256, SHA384 and SHA512.

-------------------------------------------------------------------------------------------------

Copyright (c) El Mostafa IDRASSI 2018 

mostafa.idrassi@tutanota.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

-------------------------------------------------------------------------------------------------

Copyright OpenSSL 2017

Contents licensed under the terms of the OpenSSL license

See http://www.openssl.org/source/license.html for details

-------------------------------------------------------------------------------------------------

# Cornerstones or How The Library Has Been Written

> **I) Factory class HashContext**
> - This class is the base class for all the hash-algorithm-specific derived classes.

It declares, among other methods, a : 

  - *Factory generator method* **```CreateHashContext(const hashAlgo &h)```** : returns a pointer to a hash-algorithm-specific 
  object corresponding to the argument ```hashAlgo```
  
  - *Generic method* **```initHashCtx(...)```** : initialiazes the hash context with appropriate values (e.g. initializes hash constants). 
  It shall be overriden by every hash-algorithm-specific derived class. 
  The overriden method shall call the OpenSSL method : ```alg##_Init``` where *alg##* refers to the hash algorithm in use.
  (e.g. ```SHA256_Init(...)```)
  
  - *Generic method* **```updateHashCtx(...)```** : updates the hash context internal state by hashing the input. 
  It shall be overriden by every hash-algorithm-specific derived class. 
  The overriden method shall call the OpenSSL method : ```alg##_Update``` where *alg##* refers to the hash algorithm in use.
  (e.g. ```SHA256_Update(...)```)
  
  - *Generic method* **```finalHashCtx(...)```** : outputs the hash value. 
  It shall be overriden by every hash-algorithm-specific derived class. 
  The overriden method shall call the OpenSSL method : ```alg##_Final``` where *alg##* refers to the hash algorithm in use.
  (e.g. ```SHA256_Final(...)```)
  
  - *Generic method* **```cleanup()```** : cleans up the hash context data from memory securely.
  It shall be overriden by every hash-algorithm-specific derived class. 
  The overriden method shall call ```my_memclr()``` method to securely clean the hash context data from memory.
  
> **II) Derived hash-algorithm-specific classes**
> - Example : SHA256Context class

# Some remarks

> - 2HashLib's self-test 

The library contains a self-test, implemented in the form of the following methods, each for every hash alorithm : 
```md5Test()```, ```sha1Test()```, ```sha256Test()```, ```sha384Test()```, ```sha512Test()```.

The self-tests make sure all the functions provided by the library are working as expected.

The MD5 test is based on RFC 1321.

The SHA1 and SHA2 tests are both based on FIPS 180-4 NIST test vectors (byte-oriented) : http://csrc.nist.gov/groups/STM/cavp/secure-hashing.html

> - 2HashLib doesn't make use of EVP

2HashLib makes direct calls to hash functions provided by the OpenSSL library without making use of the EVP.
