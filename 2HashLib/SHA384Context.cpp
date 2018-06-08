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

#include "SHA384Context.h"
#include "HashContext.h"

/* Openssl headers for sha256 */
#include "openssl/sha.h"

/* memclr function : safer memset(0) */
#include "SecureMemoryCleaner.h"

#include <iostream>

/*  sha256Context ctors are explicitly defined to use the default base class ctor
*   This can be ignored, thus the compiler will implictly use the default base class ctor
*/

SHA384Context::SHA384Context() : HashContext::HashContext(), sha384Ctx(new std::vector<unsigned char>(sizeof(SHA512_CTX)))
{
}

SHA384Context::~SHA384Context()
{
	this->cleanup();
}

SHA384Context::SHA384Context(const SHA384Context &orig) : HashContext::HashContext(), sha384Ctx(orig.sha384Ctx)
{
}

SHA384Context::SHA384Context(SHA384Context &&orig) : HashContext::HashContext(), sha384Ctx(orig.sha384Ctx)
{
}

int SHA384Context::initHashCtx()
{
	return (SHA384_Init((SHA512_CTX*)sha384Ctx->data()));
}

int SHA384Context::updateHashCtx(const char *inputData, const size_t &inputLength)
{
	return (SHA384_Update((SHA512_CTX*)sha384Ctx->data(), inputData, inputLength));
}
int SHA384Context::finalHashCtx(unsigned char * messageDigest)
{
	return (SHA384_Final(messageDigest, (SHA512_CTX*)sha384Ctx->data()));
}

unsigned int SHA384Context::getHashSize() const
{
	return hashSize;
}
unsigned int SHA384Context::getBlockSize() const
{
	return inputBlockSize;
}

hashAlgo SHA384Context::getHashAlgo() const
{
	return (sha384);
}

void SHA384Context::cleanup()
{
	if (false == sha384Ctx->empty()) {
		secure_memclr(sha384Ctx->data(), sha384Ctx->size());
		sha384Ctx->clear();
		sha384Ctx->shrink_to_fit();
	}
}
