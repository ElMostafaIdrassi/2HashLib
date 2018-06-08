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

/*
 * Makes sure the md5 API is working as expected
 * Based on RFC 1321 ; No NIST based test vector available
 */
int md5Test()
{
	HashContext* MD5 = HashContext::createHashContext(md5);

	/*
	* in_md5 contains the input message : abc
	*/
	unsigned char in_md5[3] = { 0x61, 0x62, 0x63 };

	/*
	* md5d will contain the digest of the input message
	*/
	unsigned char md5d[16] = {};

	/*
	*  md5_exp contains the expected digest of the input message
	*  md5_exp will be compared to md5d to determine whether the
	*      implementation of md5 has not been tempered with
	*/
	unsigned char md5_exp[16] = { 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
		0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 };

	int exitStatus = 0;

	std::cout << "Starting MD5 test 1/1 : ...";

	if (1 != MD5->initHashCtx()) exitStatus = 1;
	if (1 != MD5->updateHashCtx((char*)in_md5, 3)) exitStatus = 2;
	if (1 != MD5->finalHashCtx(md5d)) exitStatus = 3;
	if (memcmp(md5d, md5_exp, 16)) exitStatus = 4;

	MD5->cleanup();
	delete (MD5);

	if (0 == exitStatus) {
		std::cout << "Completed! \n\tMD5 test 1/1 : Successful.\n";
	}
	else {
		switch (exitStatus) {
		case 1:
			std::cout << "Terminated! \n\tMD5 test 1/1 : Failed - initCtx().\n";
			break;
		case 2:
			std::cout << "Terminated! \n\tMD5 test 1/1 : Failed - updateCtx().\n";
			break;
		case 3:
			std::cout << "Terminated! \n\tMD5 test 1/1 : Failed - finaleCtx().\n";
			break;
		case 4:
			std::cout << "Terminated! \n\tMD5 test 1/1 : Failed - memcmp().\n";
			break;
		default:
			break;
		}
	}

	return exitStatus;
}
