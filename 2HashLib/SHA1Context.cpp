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

#include "SHA1Context.h"
#include "HashContext.h"

/* Openssl headers for sha1 */
#include "openssl/sha.h"

/* memclr function : safer memset(0) */
#include "SecureMemoryCleaner.h"

#include <iostream>

/*  sha1Context ctors are explicitly defined to use the default base class ctor
*   This can be ignored, thus the compiler will implictly use the default base class ctor
*/
SHA1Context::SHA1Context() : HashContext::HashContext(), sha1Ctx(new std::vector<unsigned char>(sizeof(SHA_CTX)))
{
}

SHA1Context::~SHA1Context()
{
	this->cleanup();
}

SHA1Context::SHA1Context(const SHA1Context &orig) : HashContext::HashContext(), sha1Ctx(orig.sha1Ctx)
{
}

SHA1Context::SHA1Context(SHA1Context &&orig) : HashContext::HashContext(), sha1Ctx(orig.sha1Ctx)
{
}

int SHA1Context::initHashCtx()
{
	return (SHA1_Init((SHA_CTX*)sha1Ctx->data()));
}

int SHA1Context::updateHashCtx(const char *inputData, const size_t &inputLength)
{
	return (SHA1_Update((SHA_CTX*)sha1Ctx->data(), inputData, inputLength));
}
int SHA1Context::finalHashCtx(unsigned char * messageDigest)
{
	return (SHA1_Final(messageDigest, (SHA_CTX*)sha1Ctx->data()));
}

unsigned int SHA1Context::getHashSize() const
{
	return hashSize;
}
unsigned int SHA1Context::getBlockSize() const
{
	return inputBlockSize;
}

hashAlgo SHA1Context::getHashAlgo() const
{
	return (sha1);
}

void SHA1Context::cleanup()
{
	if (false == sha1Ctx->empty()) {
		secure_memclr(sha1Ctx->data(), sha1Ctx->size());
		sha1Ctx->clear();
		sha1Ctx->shrink_to_fit();
	}
}
