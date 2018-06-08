/*
* Copyright 2018 El Mostafa IDRASSI <mostafa.idrassi@tutanota.com>
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

#ifndef HASHCONTEXT_H
#define HASHCONTEXT_H

// Comment the following if you're building a DLL on Windows
// N.B : I'm sure there is a better way, but I'll stick to this until I find one!
//		 Make sure to modify the projet type (DLL or Static library) before building!
// #define STATIC_LIBRARY

#if defined (_WIN32) && !defined(STATIC_LIBRARY)
#  ifdef HASHCONTEXT_H
#    define HASHLIB_API __declspec(dllexport)
#  else
#    define HASHLIB_API __declspec(dllimport)
#  endif
#elif (defined (_WIN32) && defined(STATIC_LIBRARY)) || defined (UNIX) || defined (__GNUC__)
#  define HASHLIB_API
#endif

/* Standard header for size_t declaration */
#include <cstddef>

typedef HASHLIB_API enum {
	md5 = 0,
	sha1,
	sha256,
	sha384,
	sha512
} hashAlgo;

class HASHLIB_API HashContext // Factory Class
{
public:
	 virtual ~HashContext() = 0;

	 /* Factory hash context generator, uses default ctor of all hash algos  */
	 static HashContext* createHashContext(const hashAlgo &h);

	 /* Factory hashAlgo generator, uses copy ctor of all hash algos         */
	 static HashContext* createHashContext(const HashContext &orig, const hashAlgo &h);

	 /* Factory hashAlgo generator, uses move ctor of all hash algos         */
	 static HashContext* createHashContext(HashContext &&orig, const hashAlgo &h);

	 virtual int initHashCtx() = 0;
	 virtual int updateHashCtx(const char * inputData, const size_t & inputLength) = 0;
	 virtual int finalHashCtx(unsigned char * messageDigest) = 0;
	 virtual void cleanup() = 0;

protected:
	/*  It should be impossible to instanciate this class in main() (i.e. new () )
	*  thus the use of 'protected' access modifier
	*/
	HashContext();

	/*  The following "Special member functions" are deleted because not needed nor used
	*      => no implicit declaration by the compiler
	*      => no implicit or explicit use
	*  This makes the class hashContext uncopyable and unmovable
	*  All copy/move constructors defined in classes derived from hashContext
	*      will actually call implicitly hashContext default ctor, unless explicitly called (warning if not)
	*/
	HashContext(const HashContext &orig) = delete;				/*	Copy Ctor func			*/
	HashContext& operator=(const HashContext &orig) = delete;   /*  Copy Assignment func    */
	HashContext(HashContext &&orig) = delete;					/*  Move Ctor func          */
	HashContext& operator=(HashContext &&orig) = delete;		/*  Move Assignment func    */

	virtual unsigned int getHashSize() const = 0;
	virtual unsigned int getBlockSize() const = 0;
	virtual hashAlgo getHashAlgo() const = 0;

private:
};

#endif // !HASHCONTEXT_H