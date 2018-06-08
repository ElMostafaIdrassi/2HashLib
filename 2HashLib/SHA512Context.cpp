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

#include "SHA512Context.h"
#include "HashContext.h"

/* Openssl headers for sha256 */
#include "openssl/sha.h"

/* memclr function : safer memset(0) */
#include "SecureMemoryCleaner.h"

#include <iostream>

/*  sha256Context ctors are explicitly defined to use the default base class ctor
*   This can be ignored, thus the compiler will implictly use the default base class ctor
*/

SHA512Context::SHA512Context() : HashContext::HashContext(), sha512Ctx(new std::vector<unsigned char>(sizeof(SHA512_CTX)))
{
}

SHA512Context::~SHA512Context()
{
	this->cleanup();
}

SHA512Context::SHA512Context(const SHA512Context &orig) : HashContext::HashContext(), sha512Ctx(orig.sha512Ctx)
{
}

SHA512Context::SHA512Context(SHA512Context &&orig) : HashContext::HashContext(), sha512Ctx(orig.sha512Ctx)
{
}

int SHA512Context::initHashCtx()
{
	return (SHA512_Init((SHA512_CTX*)sha512Ctx->data()));
}

int SHA512Context::updateHashCtx(const char *inputData, const size_t &inputLength)
{
	return (SHA512_Update((SHA512_CTX*)sha512Ctx->data(), inputData, inputLength));
}
int SHA512Context::finalHashCtx(unsigned char * messageDigest)
{
	return (SHA512_Final(messageDigest, (SHA512_CTX*)sha512Ctx->data()));
}

unsigned int SHA512Context::getHashSize() const
{
	return hashSize;
}
unsigned int SHA512Context::getBlockSize() const
{
	return inputBlockSize;
}

hashAlgo SHA512Context::getHashAlgo() const
{
	return (sha512);
}

void SHA512Context::cleanup()
{
	if (false == sha512Ctx->empty()) {
		secure_memclr(sha512Ctx->data(), sha512Ctx->size());
		sha512Ctx->clear();
		sha512Ctx->shrink_to_fit();
	}
}
