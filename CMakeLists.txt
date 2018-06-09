# - Set the minimum version of CMake that can be used 
#   N.B. : To find the cmake version run $ cmake --version
cmake_minimum_required(VERSION 3.10.0)

# Vars to input in cli : 
#	-GNU / Clang : 
#           -DARCH:STRING="32" or "64" and -DCMAKE_BUILD_TYPE="Debug" or "Release" or ... 
#	-GNU / Clang / MSVC
#	        -DLIB_TYPE:STRING="static" or "shared"
#	        -DDIR_TO_EXT_LIBS:STRING="./external_libs" 
#		   	-DEXT_LIB_NAMES:STRING="libname1;libname2;...;libnamen" e.g. openssl
#			-DEXT_LIB_PREFIX:STRING="libpref1;libpref2;...;libprefn" e.g. libcrypto
#			contains :
#				    * static subdir
#						--	32 sub-subdir
#								---	debug 	(include, lib)
#								---	release (include, lib)
#						--	64 sub-subdir 
#								---	debug   (include, lib)
#								---	release (include, lib)
#					* shared subdir	
#						--	32 sub-subdir
#								---	debug 	(include, lib)
#								---	release (include, lib)
#						--	64 sub-subdir 
#								---	debug   (include, lib)
#								---	release (include, lib)

# - Set PROJECT_NAME & CMAKE_PROJECT_NAME value
project(2Hash)

# Enable testing for current directory and below
enable_testing()

#####################################################################
# Create the library
#####################################################################

# - Create SOURCES variable with a link to all .cpp files
# 	Can use aux_source_directory()
set(SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/2HashLib/HashContext.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/2HashLib/MD5Context.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/2HashLib/SHA1Context.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/2HashLib/SHA256Context.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/2HashLib/SHA384Context.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/2HashLib/SHA512Context.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/2HashLib/secureMemoryCleaner.cpp
)

# - Create HEADERS variable with a link to all .h files
set(HEADERS
	${CMAKE_CURRENT_SOURCE_DIR}/hashContext.h
	${CMAKE_CURRENT_SOURCE_DIR}/md5Context.h
	${CMAKE_CURRENT_SOURCE_DIR}/secureMemoryCleaner.h
)

# - Detect the usage of multiconfiguration generators 
# 	N.B : Multiconfig generators not supported on Unix
if("${CMAKE_CFG_INTDIR}" STREQUAL ".")

	MESSAGE(STATUS "Multiconfig = False")	# e.g. Make
	set(multiconfig FALSE)

else("${CMAKE_CFG_INTDIR}" STREQUAL ".")

	MESSAGE(STATUS "Multiconfig = True")	# e.g. MSVC
	set(multiconfig TRUE)
	
endif("${CMAKE_CFG_INTDIR}" STREQUAL ".")

if( CMAKE_SIZEOF_VOID_P EQUAL 8 )

	#	Host is under 64-bit arch
	MESSAGE(STATUS "CMAKE_SIZEOF_VOID_P = 8 bytes")

	if( CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" ) # or if (MSVC)

		MESSAGE("Target : 64-bit - Host : 64-bit - Compiler : MSVC")

		set (SUFFIX "64")
		set (SYS "WIN_MSVC")

		set (EXT1 "lib")
	
	elseif( ( (CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR (CMAKE_CXX_COMPILER_ID STREQUAL "Clang") ) AND (DEFINED ARCH) AND (ARCH STREQUAL "32") )

		MESSAGE(STATUS "Target : 32-bit - Host : 64-bit - Compiler : GNU / Clang")

		set (SUFFIX "32")
		if (_WIN32)
			set (SYS "WIN_GNU/CLANG")
		else(_WIN32)
			set (SYS "GNU/CLANG")
		endif(_WIN32)

		set (EXT1 "a")

	elseif( ( (CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR (CMAKE_CXX_COMPILER_ID STREQUAL "Clang") ) AND (DEFINED ARCH) AND (ARCH STREQUAL "64") )

		MESSAGE(STATUS "Target : 64-bit - Host : 64-bit - Compiler : GNU / Clang")

		set (SUFFIX "64")

		set (EXT1 "a")

	endif( CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" )
	
else( CMAKE_SIZEOF_VOID_P EQUAL 8 )

	#	Host is running 32-bit, arch = 32 or 64-bit
	MESSAGE(STATUS "CMAKE_SIZEOF_VOID_P = 4 bytes")

	if( CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" )	# or if (MSVC)

		MESSAGE(STATUS "Target : 32-bit - Host : 32 or 64-bit - Compiler : MSVC")
		set (SUFFIX "32")
		set (SYS "WIN_MSVC")
		set (EXT1 "lib")

	elseif( ( (CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR (CMAKE_CXX_COMPILER_ID STREQUAL "Clang") ) AND (DEFINED ARCH) AND (ARCH STREQUAL "32") )

		MESSAGE(STATUS "Target : 32-bit - Host : 32-bit - Compiler : GNU / Clang")
		set (SUFFIX "32")

		if (_WIN32)
			set (SYS "WIN_GNU/CLANG")
		else(_WIN32)
			set (SYS "GNU/CLANG")
		endif(_WIN32)

		set (EXT1 "a")
	
	endif( CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" )
	
endif( CMAKE_SIZEOF_VOID_P EQUAL 8 )

# -	Add a static library / shared library as a target
# -	It will be built using the specified source + header files
# -	Header files are added just so they appear in the project tree (i.e. in MSVC)
# 		N.B.1 : Target's name is not necessarily = PROJECT_NAME, but can be 
# 		N.B.2 : We're not supposed to add the header files at this step
if (LIB_TYPE STREQUAL "static")

	add_library(2Hash STATIC ${SOURCES} ${HEADERS})

	MESSAGE(STATUS "--! Merge_static_libs can only merge static libraries !--")

	if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    
   	 	# lib.exe does the merging of libraries
		# Need to convert the ; list into a string
		# CMAKE_CFG_INTDIR contains $(Configuration) : Debug, Release...

		set(lib_string "")

		foreach(lib ${EXT_LIB_NAME})

			set(lib_string "${lib_string} ${DIR_TO_EXT_LIB}/static/${SUFFIX}/${CMAKE_CFG_INTDIR}/lib/${lib}.lib")

		endforeach()

		if (SUFFIX STREQUAL "32")
			add_custom_target(merge
				COMMAND LIB.EXE /MACHINE:X86 /OUT:2Hash.lib ${lib_string}
				DEPENDS 2Hash)

		elseif (SUFFIX STREQUAL "64")
			add_custom_target(merge
				COMMAND LIB.EXE /MACHINE:X64 /OUT:2Hash.lib ${CMAKE_SOURCE_DIR}/${lib_string}
				DEPENDS 2Hash
			)

		endif(SUFFIX STREQUAL "32")

	elseif( (CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR (CMAKE_CXX_COMPILER_ID STREQUAL "Clang") )

		# general UNIX - need to "ar -x" and then "ar -ru" ! WRONG ! 

		if(multiconfig)
			message(FATAL_ERROR "Multi-configurations are not supported")
		endif(multiconfig)

		foreach(lib ${EXT_LIB_NAME})

			set(lib_string "${lib_string} ${DIR_TO_EXT_LIB}/static/${SUFFIX}/${CMAKE_BUILD_TYPE}/lib/${lib}.a")

		endforeach()

		add_custom_target(merge
			COMMAND ar -cq lib2Hash.a ${CMAKE_SOURCE_DIR}/${lib_string}
			DEPENDS 2Hash
		)

		# 	Or execute this MRI script
		#
		#	create 2Hash.a
		#	addlib lib1.a
		#	addlib lib2.a
		#	save
		#	end

	endif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")


elseif(LIB_TYPE STREQUAL "shared")

	add_library(2Hash SHARED ${SOURCES} ${HEADERS})

	# Statically linking external static libraries to this shared library

	if ( DEFINED DIR_TO_EXT_LIB )	# points to the static libraries

		foreach(lib ${EXT_LIB_NAME})

			set(libname "${lib}_debug")

			find_library(LIB NAMES ${lib}.${EXT1} PATHS "${DIR_TO_EXT_LIB}/static/${SUFFIX}/Debug/lib" NO_DEFAULT_PATH)
			target_link_libraries( 2Hash PRIVATE debug ${LIB})
			MESSAGE(STATUS "Linking against ${SUFFIX}-bit static ${libname} (${SYS})")

			set(libname "${lib}_optimized")

			find_library(LIB NAMES ${lib}.${EXT1} PATHS "${DIR_TO_EXT_LIB}/static/${SUFFIX}/Release/lib" NO_DEFAULT_PATH)
			target_link_libraries( 2Hash PRIVATE optimized ${LIB})
			MESSAGE(STATUS "Linking against ${SUFFIX}-bit static ${libname} (${SYS})")

		endforeach()

	else ( DEFINED DIR_TO_EXT_LIB )
	
		MESSAGE(STATUS "DIR_TO_EXT_LIB variable not set. Using system libraries for all configurations...")
		MESSAGE(STATUS "!----Note that pre-built libraries in the system usually don't include debugging symbols and may sometimes be absent----!")

		foreach(lib ${EXT_LIBS_LIST})

			find_library(LIB NAMES ${lib}.${EXT1})
			target_link_libraries( 2Hash PRIVATE general ${LIB})
			MESSAGE(STATUS "Linking against ${SUFFIX}-bit static ${lib}-general from system built-in libraries (${SYS})")

		endforeach()

	endif( DEFINED DIR_TO_EXT_LIB )

	if( (CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR (CMAKE_CXX_COMPILER_ID STREQUAL "Clang") )

		set_target_properties(2Hash PROPERTIES
			LINK_FLAGS "-m${SUFFIX} -Wextra -Wall"
		)

	endif( (CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR (CMAKE_CXX_COMPILER_ID STREQUAL "Clang") )
		
endif(LIB_TYPE STREQUAL "static")

# - Generate export header automatically
include (GenerateExportHeader)          
generate_export_header( 2Hash           			# generates the export header LIB_2HASH_EXPORTS.h automatically in ${CMAKE_CURRENT_BINARY_DIR}
    BASE_NAME LIB_2HASH_EXPORTS
    EXPORT_MACRO_NAME LIB_2HASH_EXPORTS
    EXPORT_FILE_NAME LIB_2HASH_EXPORTS.h
    STATIC_DEFINE SHARED_EXPORTS_BUILT_AS_STATIC 	# ?
)

# - Set the location for library installation
# -	Either : 
# 		- user defines CMAKE_INSTALL_PREFIX in command line using -D parameter (-DCMAKE_INSTALL_PREFIX="...")
#		or
#		- user sets it here in CMakeLists.txt  
# - Otherwise, it defaults to : /usr/local (unix), C:/Program Files/${PROJECT_NAME} (Windows)
set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/out/2Hash/${LIB_TYPE}/${SUFFIX}" CACHE PATH "..." FORCE)

message(STATUS "CMAKE_INSTALL_PREFIX = ${CMAKE_INSTALL_PREFIX}")

# - Add include directories to target 
# - Specify include directories to use when compiling a given target
# - Populates INCLUDE_DIRECTORIES (PRIVATE / PUBLIC) and/or INTERFACE_INCLUDE_DIRECTORIES (PUBLIC / INTERFACE) properties
#		N.B.1 : INCLUDE_DIRECTORIES 			= List of preprocessor include file search directories
#												= used by the generators to set the include paths for the compiler
#		N.B.2 : INTERFACE_INCLUDE_DIRECTORIES 	= List of public include directories requirements for a library
#												= used to publish the include directories required to compile against the headers for the target
#													(makes the directory visible/accessible to targets linking to this target/library)
target_include_directories( 2Hash
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
	PUBLIC ${CMAKE_CURRENT_BINARY_DIR}						# the build tree parent, where LIB_2HASH_EXPORTS.h is located
	PRIVATE ${DIR_TO_EXT_LIB}/${SUFFIX}/Debug/include
	PRIVATE ${DIR_TO_EXT_LIB}/${SUFFIX}/Release/include
)

# - Set an alias [ ${CMAKE_PROJECT_NAME}::lib ] to refer to this library [ <target> = A ]
# 		N.B. : The alias can be used as : 
#		       -	a linkable target (i.e. link to an exe) 
#		       -	as a target to read properties from (i.e. get_property())
add_library( ${CMAKE_PROJECT_NAME}::lib ALIAS 2Hash)

# - Set properties that affect how target is built
# 		N.B. : 	PIC 					=>	Useful if static library will be, in the future, statically linked to a shared library
#											Unix only, no Windows PIC needed
#				CXX_EXTENSIONS "OFF"	=>	will only use -std=c++11 (ISO) (appended)
set_target_properties(2Hash PROPERTIES 
	POSITION_INDEPENDENT_CODE "True"
	CXX_STANDARD "11"
	CXX_STANDARD_REQUIRED "ON"
	CXX_EXTENSIONS "OFF"				# will only use -std=c++11 (ISO) (appended)
	LINKER_LANGUAGE "CXX"				# otherwise, get error <CMake can not determine linker language for target>

	# ARCHIVE_OUTPUT_NAME "$<IF:$<CONFIG:Debug>,2Hash${Post}${SUFFIX}d,2Hash${Post}${SUFFIX}>"
	# LIBRARY_OUTPUT_NAME "$<IF:$<CONFIG:Debug>,2Hash${Post}${SUFFIX}d,2Hash${Post}${SUFFIX}>"
	# RUNTIME_OUTPUT_NAME "$<IF:$<CONFIG:Debug>,2Hash${Post}${SUFFIX}d,2Hash${Post}${SUFFIX}>"

)

# - Add compile options to a target, to be used when compiling the target
# - Populates COMPILE_OPTIONS (PRIVATE / PUBLIC) and/or INTERFACE_COMPILE_OPTIONS (PUBLIC / INTERFACE) properties
#		N.B.1 : COMPILE_OPTIONS 			= ';' separated list of options to pass to the compiler
#											= used by the generators to set the options for the compiler
#		N.B.2 : INTERFACE_COMPILE_OPTIONS 	= List of public compile options requirements for a library.
#											= used to publish the compile options required to compile against the headers for the target
target_compile_options( 2Hash
	# If the same sources are used to create both a shared and a static library,
	# 	then the following option will cause the export macros to expand to nothing when building the static library
	PUBLIC "-DLIB_2HASH_EXPORTS_STATIC_DEFINE"												
	PUBLIC "$<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-m${ARCH};-Wextra;-Wall;-Wpedantic>"
	PUBLIC "$<$<AND:$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>,$<CONFIG:Debug>>:-O0>"
)

# - Specify rules to run at install time
# 		N.B.1 : Paths are relative to CMAKE_INSTALL_PREFIX variable
# 		N.B.2 :	INCLUDES specifies list of directories which will be added to the INTERFACE_INCLUDE_DIRECTORIES when exported by the install(EXPORT) command
#					i.e. for when an executable links to a library, so that it knows where to find include files
install(TARGETS 2Hash
        ARCHIVE CONFIGURATIONS Debug DESTINATION Debug/lib		# .a   (Unix) / .lib (Win32 : static + imported lib)
        LIBRARY CONFIGURATIONS Debug DESTINATION Debug/lib 		# .so  (Unix)
        RUNTIME CONFIGURATIONS Debug DESTINATION Debug/bin		# .dll (Win32)
        	# on Windows, a DLL is considered as Runtime, and a DLL's imported library as ARCHIVE
        INCLUDES CONFIGURATIONS Debug DESTINATION Debug/include/2Hash
)
install(TARGETS 2Hash
        ARCHIVE CONFIGURATIONS Release DESTINATION Release/lib		# .a   (Unix) / .lib (Win32 : static + imported lib)
        LIBRARY CONFIGURATIONS Release DESTINATION Release/lib 		# .so  (Unix)
        RUNTIME CONFIGURATIONS Release DESTINATION Release/bin		# .dll (Win32)
        	# on Windows, a DLL is considered as Runtime, and a DLL's imported library as ARCHIVE
        INCLUDES CONFIGURATIONS Release DESTINATION Release/include/2Hash
)

# - Copy the headers of the library 
install(FILES hashContext.h CONFIGURATIONS Debug DESTINATION Debug/include/2Hash RENAME "2Hash.h")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/LIB_2HASH_EXPORTS.h DESTINATION Debug/include/2Hash)
install(FILES hashContext.h CONFIGURATIONS Release DESTINATION Release/include/2Hash RENAME "2Hash.h")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/LIB_2HASH_EXPORTS.h DESTINATION Release/include/2Hash)

# - Add test subproject
# - Creates subdirectory in build directory and launches CMakeLists.txt in <path-to-source-directory>/test
add_subdirectory(test)

# - Add "check" as target
# - Usage : cd <path-to-build-dir> && make check
add_custom_target(check
	COMMAND ${CMAKE_CTEST_COMMAND} --verbose
		#${CMAKE_CTEST_COMMAND} -C $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:${CMAKE_BUILD_TYPE}>
	DEPENDS 2Hash 2HashTest
)

# - Add a selftest 
add_test(NAME 2HashSelfTest
	COMMAND 2HashTest
)