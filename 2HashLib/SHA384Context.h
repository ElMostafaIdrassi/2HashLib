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

/* Factory class header */
#include "HashContext.h"

/* Standard header for vectors */
#include <vector>

/* final class : cannot be derived from, cannot be extended */
class SHA384Context final :
	public HashContext
{
public:
	SHA384Context();
	~SHA384Context();

	SHA384Context(const SHA384Context &orig);
	SHA384Context& operator=(const SHA384Context &orig) = delete;
	SHA384Context(SHA384Context &&orig);
	SHA384Context& operator=(SHA384Context &&orig) = delete;

	int initHashCtx() override;
	int updateHashCtx(const char *inputData, const size_t &inputLength) override;
	int finalHashCtx(unsigned char *messageDigest) override;
	void cleanup() override;

	unsigned int getHashSize() const override;
	unsigned int getBlockSize() const override;
	hashAlgo getHashAlgo() const override;

private:
	static const unsigned int hashSize = 48U;
	static const unsigned int inputBlockSize = 128U;

	/*  When exporting a DLL on Windows/MSVC which containes a class that uses a vector as a member ( = STL structure),
	*      MSVC prompts with a warning saying that
	*      " class 'std::vector<unsigned char,std::allocator<_Ty>>' needs to have dll-interface to be used by clients of class 'myClass' "
	*
	*  This is due to the fact that the size of the STL member (vector here) is not always the same (a vector can grow dynamically), leading to
	*      the size of the exported class not being always the same
	*  One way of fixing this is to declare a pointer to the STL structure, which guarantees a fixed size of the member (= pointer size = address size)
	*
	*  See : https://stackoverflow.com/questions/4145605/stdvector-needs-to-have-dll-interface-to-be-used-by-clients-of-class-xt-war
	*/
	std::vector<unsigned char> * sha384Ctx = nullptr;
};