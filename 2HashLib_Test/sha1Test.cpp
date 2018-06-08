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

#include <iostream>
#include <cstring>

#include "HashContext.h"

/*  ====================================================================
 *	Makes sure the sha1 API is working as expected
 *	Based on FIPS 180-4 NIST test vectors (byte-oriented) : http://csrc.nist.gov/groups/STM/cavp/secure-hashing.html
 */
int sha1Test()
{
	HashContext * SHA1 = HashContext::createHashContext(sha1);

	/*
	* in_short_sha1 contains the input short test vector
	* in_long_sha1 contains the input long test vector
	*/
	unsigned char in_short_sha1[7] = { 0x63, 0xbf, 0xc1, 0xed, 0x7f, 0x78, 0xab };
	unsigned char in_long_sha1[163] = { 0x7c, 0x9c, 0x67, 0x32, 0x3a, 0x1d, 0xf1, 0xad,
		0xbf, 0xe5, 0xce, 0xb4, 0x15, 0xea, 0xef, 0x01,
		0x55, 0xec, 0xe2, 0x82, 0x0f, 0x4d, 0x50, 0xc1,
		0xec, 0x22, 0xcb, 0xa4, 0x92, 0x8a, 0xc6, 0x56,
		0xc8, 0x3f, 0xe5, 0x85, 0xdb, 0x6a, 0x78, 0xce,
		0x40, 0xbc, 0x42, 0x75, 0x7a, 0xba, 0x7e, 0x5a,
		0x3f, 0x58, 0x24, 0x28, 0xd6, 0xca, 0x68, 0xd0,
		0xc3, 0x97, 0x83, 0x36, 0xa6, 0xef, 0xb7, 0x29,
		0x61, 0x3e, 0x8d, 0x99, 0x79, 0x01, 0x62, 0x04,
		0xbf, 0xd9, 0x21, 0x32, 0x2f, 0xdd, 0x52, 0x22,
		0x18, 0x35, 0x54, 0x44, 0x7d, 0xe5, 0xe6, 0xe9,
		0xbb, 0xe6, 0xed, 0xf7, 0x6d, 0x7b, 0x71, 0xe1,
		0x8d, 0xc2, 0xe8, 0xd6, 0xdc, 0x89, 0xb7, 0x39,
		0x83, 0x64, 0xf6, 0x52, 0xfa, 0xfc, 0x73, 0x43,
		0x29, 0xaa, 0xfa, 0x3d, 0xcd, 0x45, 0xd4, 0xf3,
		0x1e, 0x38, 0x8e, 0x4f, 0xaf, 0xd7, 0xfc, 0x64,
		0x95, 0xf3, 0x7c, 0xa5, 0xcb, 0xab, 0x7f, 0x54,
		0xd5, 0x86, 0x46, 0x3d, 0xa4, 0xbf, 0xea, 0xa3,
		0xba, 0xe0, 0x9f, 0x7b, 0x8e, 0x92, 0x39, 0xd8,
		0x32, 0xb4, 0xf0, 0xa7, 0x33, 0xaa, 0x60, 0x9c,
		0xc1, 0xf8, 0xd4 };

	/*
	* sha1d will contain the digest of the input message
	*/
	unsigned char sha1d[20];

	/*
	*  sha1_sexp and sha1_lexp contain the expected digests of the inputs messages
	*  They will be compared to sha1d to determine whether the
	*      implementation of sha1 has not been tempered with
	*/
	unsigned char sha1_sexp[20] = {
		0x86, 0x03, 0x28, 0xd8, 0x05, 0x09, 0x50, 0x0c,
		0x17, 0x83, 0x16, 0x9e, 0xbf, 0x0b, 0xa0, 0xc4,
		0xb9, 0x4d, 0xa5, 0xe5
	};
	unsigned char sha1_lexp[20] = {
		0xd8, 0xfd, 0x6a, 0x91, 0xef, 0x3b, 0x6c, 0xed,
		0x05, 0xb9, 0x83, 0x58, 0xa9, 0x91, 0x07, 0xc1,
		0xfa, 0xc8, 0xc8, 0x07
	};

	int exitStatus1 = 0;

	std::cout << "Starting SHA1 test 1/2 : ...";

	if (1 != SHA1->initHashCtx()) exitStatus1 = 1;
	if (1 != SHA1->updateHashCtx((char*)in_short_sha1, 7)) exitStatus1 = 2;
	if (1 != SHA1->finalHashCtx(sha1d)) exitStatus1 = 3;
	if (memcmp(sha1d, sha1_sexp, 20)) exitStatus1 = 4;
	
	SHA1->cleanup();

	if (0 == exitStatus1) {
		std::cout << "Completed! \n\tSHA1 test 1/2 : Successful.\n";
	}
	else {
		switch (exitStatus1) {
		case 1:
			std::cout << "Terminated! \n\tSHA1 test 1/2 : Failed - initCtx().\n";
			break;
		case 2:
			std::cout << "Terminated! \n\tSHA1 test 1/2 : Failed - updateCtx().\n";
			break;
		case 3:
			std::cout << "Terminated! \n\tSHA1 test 1/2 : Failed - finaleCtx().\n";
			break;
		case 4:
			std::cout << "Terminated! \n\tSHA1 test 1/2 : Failed - memcmp().\n";
			break;
		default:
			break;
		}
	}
	
	SHA1 = HashContext::createHashContext(sha1);

	std::cout << "Starting SHA1 test 2/2 : ...";

	int exitStatus2 = 0;

	if (1 != SHA1->initHashCtx()) exitStatus2 = 1;
	if (1 != SHA1->updateHashCtx((char*)in_long_sha1, 163)) exitStatus2 = 2;
	if (1 != SHA1->finalHashCtx(sha1d)) exitStatus2 = 3;
	if (memcmp(sha1d, sha1_lexp, 20)) exitStatus2 = 4;

	SHA1->cleanup();

	if (0 == exitStatus2) {
		std::cout << "Completed! \n\tSHA1 test 2/2 : Successful.\n";
	}
	else {
		switch (exitStatus2) {
		case 1:
			std::cout << "Terminated! \n\tSHA1 test 2/2 : Failed - initCtx().\n";
			break;
		case 2:
			std::cout << "Terminated! \n\tSHA1 test 2/2 : Failed - updateCtx().\n";
			break;
		case 3:
			std::cout << "Terminated! \n\tSHA1 test 2/2 : Failed - finaleCtx().\n";
			break;
		case 4:
			std::cout << "Terminated! \n\tSHA1 test 2/2 : Failed - memcmp().\n";
			break;
		default:
			break;
		}
	}

	delete(SHA1);

	if (exitStatus1 != 0) return exitStatus1;
	if (exitStatus2 != 0) return exitStatus2;
	return 0;
}