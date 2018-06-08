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

#include "SecureMemoryCleaner.h"

volatile void* secure_memset(void *ptr, const int &value, size_t num)
{
	volatile unsigned char *buf;
	buf = (volatile unsigned char*)ptr;

	while (num)
		buf[--num] = (unsigned char)value;

	return (volatile void*)ptr;
}

volatile void* secure_memclr(void *ptr, size_t num) {
	return (secure_memset(ptr, 0, num));
}