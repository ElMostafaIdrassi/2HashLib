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

#include "SHA256Context.h"
#include "HashContext.h"

/* Openssl headers for sha256 */
#include "openssl/sha.h"

/* memclr function : safer memset(0) */
#include "SecureMemoryCleaner.h"

#include <iostream>

/*  sha256Context ctors are explicitly defined to use the default base class ctor
*   This can be ignored, thus the compiler will implictly use the default base class ctor
*/

SHA256Context::SHA256Context() : HashContext::HashContext(), sha256Ctx(new std::vector<unsigned char>(sizeof(SHA256_CTX)))
{
}

SHA256Context::~SHA256Context()
{
	this->cleanup();
}

SHA256Context::SHA256Context(const SHA256Context &orig) : HashContext::HashContext(), sha256Ctx(orig.sha256Ctx)
{
}

SHA256Context::SHA256Context(SHA256Context &&orig) : HashContext::HashContext(), sha256Ctx(orig.sha256Ctx)
{
}

int SHA256Context::initHashCtx()
{
	return (SHA256_Init((SHA256_CTX*)sha256Ctx->data()));
}

int SHA256Context::updateHashCtx(const char *inputData, const size_t &inputLength)
{
	return (SHA256_Update((SHA256_CTX*)sha256Ctx->data(), inputData, inputLength));
}
int SHA256Context::finalHashCtx(unsigned char * messageDigest)
{
	return (SHA256_Final(messageDigest, (SHA256_CTX*)sha256Ctx->data()));
}

unsigned int SHA256Context::getHashSize() const
{
	return hashSize;
}
unsigned int SHA256Context::getBlockSize() const
{
	return inputBlockSize;
}

hashAlgo SHA256Context::getHashAlgo() const
{
	return (sha256);
}

void SHA256Context::cleanup()
{
	if (false == sha256Ctx->empty()) {
		secure_memclr(sha256Ctx->data(), sha256Ctx->size());
		sha256Ctx->clear();
		sha256Ctx->shrink_to_fit();
	}
}
