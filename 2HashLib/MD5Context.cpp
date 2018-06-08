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

#include "MD5Context.h"
#include "HashContext.h"

/* Openssl headers for MD5 */
#include "openssl/md5.h"

/* memclr function : safer memset(0) */
#include "SecureMemoryCleaner.h"

#include <iostream>

/*  md5Context ctors are explicitly defined to use the default base class ctor
*   This can be ignored, thus the compiler will implictly use the default base class ctor
*/
MD5Context::MD5Context() : HashContext::HashContext(), md5Ctx(new std::vector<unsigned char>(sizeof(MD5_CTX)))
{
}

MD5Context::~MD5Context()
{
	this->cleanup();
}

MD5Context::MD5Context(const MD5Context &orig) : HashContext::HashContext(), md5Ctx(orig.md5Ctx)
{
}

MD5Context::MD5Context(MD5Context &&orig) : HashContext::HashContext(), md5Ctx(orig.md5Ctx)
{
}

int MD5Context::initHashCtx()
{
	return (MD5_Init((MD5_CTX*)md5Ctx->data()));
}

int MD5Context::updateHashCtx(const char *inputData, const size_t &inputLength)
{
	return (MD5_Update((MD5_CTX*)md5Ctx->data(), inputData, inputLength));
}
int MD5Context::finalHashCtx(unsigned char * messageDigest)
{
	return (MD5_Final(messageDigest, (MD5_CTX*)md5Ctx->data()));
}

unsigned int MD5Context::getHashSize() const
{
	return hashSize;
}
unsigned int MD5Context::getBlockSize() const
{
	return inputBlockSize;
}

hashAlgo MD5Context::getHashAlgo() const
{
	return (md5);
}

void MD5Context::cleanup()
{
	if (false == md5Ctx->empty()) {
		secure_memclr(md5Ctx->data(), md5Ctx->size());
		md5Ctx->clear();
		md5Ctx->shrink_to_fit();
	}
}