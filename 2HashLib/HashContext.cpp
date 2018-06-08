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

#include "HashContext.h"
#include "MD5Context.h"
#include "SHA1Context.h"
#include "SHA256Context.h"
#include "SHA384Context.h"
#include "SHA512Context.h"

/* Standard header for cerr and co functions */
#include <iostream>

HashContext::~HashContext()
{
}

HashContext::HashContext()
{
}

HashContext* HashContext::createHashContext(const hashAlgo &h)
{
	switch (h) {

	case md5:
		return (new MD5Context());
		break;
		
	case sha1:
		return (new SHA1Context());
		break;

	case sha256:
		return (new SHA256Context());
		break;

	case sha384:
		return (new SHA384Context());
		break;

	case sha512:
		return (new SHA512Context());
		break;
		
	default:
		std::cerr << "Unknown hash algorithm.\nAvailable hash algorithms are : md5, sha1, sha256/384/512.\n";
		return (nullptr);
		break;

	}
}

HashContext* HashContext::createHashContext(const HashContext &orig, const hashAlgo &h)
{
	switch (h) {

	case md5:
		return (new MD5Context((MD5Context&)orig));
		break;
		
	case sha1:
		return (new SHA1Context((SHA1Context&)orig));
		break;

	case sha256:
		return (new SHA256Context((SHA256Context&)orig));
		break;

	case sha384:
		return (new SHA384Context((SHA384Context&)orig));
		break;

	case sha512:
		return (new SHA512Context((SHA512Context&)orig));
		break;
		
	default:
		std::cerr << "Unknown hash algorithm.\nAvailable hash algorithms are : md5, sha1, sha256/384/512.\n";
		return (nullptr);
		break;

	}
}

HashContext* HashContext::createHashContext(HashContext &&orig, const hashAlgo &h)
{
	switch (h) {

	case md5:
		return (new MD5Context((MD5Context&&)orig));
		break;

	case sha1:
		return (new SHA1Context((SHA1Context&&)orig));
		break;

	case sha256:
		return (new SHA256Context((SHA256Context&&)orig));
		break;

	case sha384:
		return (new SHA384Context((SHA384Context&&)orig));
		break;

	case sha512:
		return (new SHA512Context((SHA512Context&&)orig));
		break;

	default:
		std::cerr << "Unknown hash algorithm.\nAvailable hash algorithms are : md5, sha1, sha256/384/512.\n";
		return (nullptr);
		break;

	}
}