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

#include "2HashLibTest.h"
#include <iostream>

int main()
{
	int iStatus = 0;

	//std::cout << (0 == HashLib_Init() ? "Hash library initialization OK.\n" : "Hash library initialization KO.\n");
	
	iStatus = md5Test();
	if (iStatus != 0)
	{
		std::cout << "Hash library initialization KO - MD5 test Failed!\n";
		return iStatus;
	}
	else 
	{
		iStatus = sha1Test();
		if (iStatus != 0)
		{
			std::cout << "Hash library initialization KO - SHA1 test Failed!\n";
			return iStatus;
		}
		else 
		{
			iStatus = sha256Test();
			if (iStatus != 0) 
			{
				std::cout << "Hash library initialization KO - SHA256 test Failed!\n";
				return iStatus;
			}
			else
			{
				iStatus = sha384Test();
				if (iStatus != 0)
				{
					std::cout << "Hash library initialization KO - SHA384 test Failed!\n";
					return iStatus;
				}
				else
				{
					iStatus = sha512Test();
					if (iStatus != 0)
					{
						std::cout << "Hash library initialization KO - SHA512 test Failed!\n";
						return iStatus;
					}
					else
					{
						std::cout << "Hash library initialization OK - All tests succeeded!\n";
						return 0;
					}
				}
			}		
		}		
	}
}

