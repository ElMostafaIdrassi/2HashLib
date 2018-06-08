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

#ifndef SECUREMEMORYCLEANER_H
#define SECUREMEMORYCLEANER_H

#include <cstddef>

/* memset implementation which counters agressive dead-code elimination by some compilers */
volatile void* secure_memset(void *ptr, const int &value, size_t num);

volatile void* secure_memclr(void *ptr, size_t num);

#endif /* SECUREMEMORYCLEANER_H */
