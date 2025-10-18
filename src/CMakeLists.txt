# ZMQ
find_package(ZeroMQ 4.1.5 REQUIRED)

# Jansson
set(JANSSON_BUILD_DOCS OFF CACHE BOOL "Disable docs")
set(JANSSON_EXAMPLES OFF CACHE BOOL "Disable examples")
set(JANSSON_WITHOUT_TESTS ON CACHE BOOL "No tests")
set(JANSSON_INSTALL OFF CACHE BOOL "No install target")
set(JANSSON_BUILD_SHARED_LIBS OFF CACHE BOOL "Use static lib only")
add_subdirectory(jansson-2.14)
include_directories(AFTER ${CMAKE_BINARY_DIR}/src/jansson-2.14/include ${CMAKE_SOURCE_DIR}/src/jansson-2.14/src)

# Set LIBS
set(LIBS asicseerpool jansson)
find_library(LIB_M m)
if(LIB_M)
    set(LIBS ${LIBS} m)
endif()
find_library(LIB_RT rt)
if(LIB_RT)
    set(LIBS ${LIBS} rt)
endif()
find_library(LIB_PTHREAD pthread)
if(LIB_PTHREAD)
    set(LIBS ${LIBS} pthread)
endif()

option(USE_ASM "Use assembly version of sha256 hasher" ON)
if(USE_ASM)
    add_compile_definitions(USE_ASM=1)
endif()

add_library(asicseerpool libasicseerpool.c libasicseerpool_cxx.cpp libasicseerpool.h sha2.h cashaddr.cpp cashaddr.h
                         bitcoin/random.cpp bitcoin/sha256.cpp bitcoin/sha256_sse4.cpp bitcoin/sha512.cpp
                         libasicseerpool_platform_specific.cpp
)

add_executable(asicseer-pool asicseer-pool.c asicseer-pool.h generator.c generator.h bitcoin.c bitcoin.h
                             stratifier.c stratifier.h connector.c connector.h uthash.h utlist.h donation.h empty.cpp)
target_link_libraries(asicseer-pool ${LIBS} ZeroMQ::zmq)

add_executable(asicseer-pmsg asicseer-pmsg.c empty.cpp)
target_link_libraries(asicseer-pmsg ${LIBS})

add_executable(notifier notifier.c empty.cpp)
target_link_libraries(notifier ${LIBS})

add_executable(summariser summariser.c empty.cpp)
target_link_libraries(summariser ${LIBS})

option(ENABLE_TESTS "Enable unit tests" OFF)
if(ENABLE_TESTS)
    add_executable(tests tests.cpp)
    target_link_libraries(tests ${LIBS})
endif()

# ------------------------------------------- config.h generation -------------------------------------------
# This generates config.h which provides numerous defines about the state of the platform we are building on.
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckCSourceCompiles)
include(CheckCXXSourceCompiles)

# Version
set(APP_VERSION_MAJOR ${asicseer-pool_VERSION_MAJOR})
set(APP_VERSION_MINOR ${asicseer-pool_VERSION_MINOR})
set(APP_VERSION_REVISION ${asicseer-pool_VERSION_PATCH})
set(APP_BUGREPORT ${asicseer-pool_HOMEPAGE_URL})
set(APP_NAME "asicseer-pool")

# Various tests
check_include_files("alloca.h" HAVE_ALLOCA_H)
if(HAVE_ALLOCA_H)
    check_c_source_compiles("#include <alloca.h>
        int main(void)
        {
            void *buf = alloca(1);
            return 0;
        }" HAVE_ALLOCA)
endif()
check_include_files("arpa/inet.h" HAVE_ARPA_INET_H)
check_include_files("byteswap.h" HAVE_BYTESWAP_H)
if(HAVE_BYTESWAP_H)
    check_symbol_exists(bswap_16 "byteswap.h" HAVE_DECL_BSWAP_16)
    check_symbol_exists(bswap_32 "byteswap.h" HAVE_DECL_BSWAP_32)
    check_symbol_exists(bswap_64 "byteswap.h" HAVE_DECL_BSWAP_64)
endif()
check_include_files("ctype.h" HAVE_CTYPE_H)
check_include_files("dirent.h" HAVE_DIRENT_H)
check_include_files("dlfcn.h" HAVE_DLFCN_H)
check_include_files("endian.h" HAVE_ENDIAN_H)
check_include_files("errno.h" HAVE_ERRNO_H)
check_include_files("fcntl.h" HAVE_FCNTL_H)
check_include_files("fenv.h" HAVE_FENV_H)
check_include_files("getopt.h" HAVE_GETOPT_H)
check_include_files("grp.h" HAVE_GRP_H)
check_include_files("inttypes.h" HAVE_INTTYPES_H)
check_include_files("linux/un.h" HAVE_LINUX_UN_H)
check_include_files("math.h" HAVE_MATH_H)
check_include_files("memory.h" HAVE_MEMORY_H)
check_include_files("netdb.h" HAVE_NETDB_H)
check_include_files("netinet/in.h" HAVE_NETINET_IN_H)
check_include_files("netinet/tcp.h" HAVE_NETINET_TCP_H)
check_include_files("poll.h" HAVE_POLL_H)
check_include_files("pthread_np.h" HAVE_PTHREAD_NP_H)
check_include_files("sys/endian.h" HAVE_SYS_ENDIAN_H)
check_include_files("sys/epoll.h" HAVE_SYS_EPOLL_H)
if(HAVE_SYS_EPOLL_H)
    check_symbol_exists(epoll_create1 "sys/epoll.h" HAVE_EPOLL)
endif()
check_include_files("sys/event.h" HAVE_SYS_EVENT_H)
if(HAVE_SYS_EVENT_H)
    check_symbol_exists(kevent "sys/event.h" HAVE_KEVENT)
endif()
check_include_files("sys/ioctl.h" HAVE_SYS_IOCTL_H)
check_include_files("sys/poll.h" HAVE_SYS_POLL_H)
check_include_files("sys/prctl.h" HAVE_SYS_PRCTL_H)
check_include_files("sys/resource.h" HAVE_SYS_RESOURCE_H)
if(HAVE_SYS_RESOURCE_H)
    check_symbol_exists(getrlimit "sys/resource.h" HAS_GETRLIMIT)
    check_symbol_exists(setrlimit "sys/resource.h" HAS_SETRLIMIT)
endif()
check_include_files("sys/select.h" HAVE_SYS_SELECT_H)
check_include_files("sys/socket.h" HAVE_SYS_SOCKET_H)
check_include_files("sys/stat.h" HAVE_SYS_STAT_H)
check_include_files("sys/time.h" HAVE_SYS_TIME_H)
check_include_files("sys/types.h" HAVE_SYS_TYPES_H)
check_include_files("time.h" HAVE_TIME_H)
check_include_files("unistd.h" HAVE_UNISTD_H)
check_c_source_compiles("#include <sys/types.h>
    int main(void)
    {
        size_t i;
        return i = 0;
    }" HAVE_size_t)
if(NOT HAVE_size_t)
set(size_t "unsigned int")
endif()
check_c_source_compiles("#include <stdlib.h>
    int main(void)
    {
        unsigned r;
        r = arc4random();
        r = arc4random_uniform(10);
        return 0;
    }" HAVE_ARC4RANDOM)
check_c_source_compiles("#include <time.h>
    int main(void)
    {
        struct timespec ts_end = {0, 0};
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts_end, 0);
        return 0;
    }" HAVE_CLOCK_NANOSLEEP)
check_c_source_compiles("#define _GNU_SOURCE
#include <string.h>
    int main(int argc, char *argv[])
    {
        char *dup = strdupa(argc ? argv[0] : \"foo\");
        return 0;
    }" HAVE_STRDUPA)
check_cxx_source_compiles("#include <cstdint>
    int main() {
        using u128 = unsigned __int128;
        u128 val = 42;
        return (val * val) / (42 * 42) - 1;
    }
" HAVE_INT128)
check_c_source_compiles("#include <pthread.h>
    int main(void) {
        pthread_mutex_timedlock((pthread_mutex_t *)0, (struct timespec *)0);
        return 0;
    }" HAVE_PTHREAD_MUTEX_TIMEDLOCK)
check_c_source_compiles("#include <pthread.h>
    int main(void) {
        pthread_rwlock_timedwrlock((pthread_rwlock_t *)0, (struct timespec *)0);
        return 0;
    }" HAVE_PTHREAD_RWLOCK_TIMEDWRLOCK)
check_c_source_compiles("#include <pthread.h>
    int main(void) {
        pthread_rwlock_timedrdlock((pthread_rwlock_t *)0, (struct timespec *)0);
        return 0;
    }" HAVE_PTHREAD_RWLOCK_TIMEDRDLOCK)
check_c_source_compiles("#include <stdlib.h>
#   include <stdint.h>
    int main(void) {
        initstate_r(0, (char *)0, 0, (struct random_data *)0);
        return random_r((struct random_data *)0, (int32_t *)0);
    }" HAVE_RANDOM_R)
# Endianness
check_cxx_source_compiles("int main(void) { return 0; }
#   ifndef __BYTE_ORDER__
#       include <bit>
        static_assert(std::endian::native == std::endian::big);
#   else
        static_assert(__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__);
#   endif" WORDS_BIGENDIAN)
check_cxx_source_compiles("int main(void) { return 0; }
#   ifndef __BYTE_ORDER__
#       include <bit>
        static_assert(std::endian::native == std::endian::little);
#   else
        static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);
#   endif" WORDS_LITTLEENDIAN)
if(HAVE_ENDIAN_H)
        set(ENDIAN_FILE "endian.h")
elseif(HAVE_SYS_ENDIAN_H)
        set(ENDIAN_FILE "sys/endian.h")
else()
endif()
if(ENDIAN_FILE)
    check_symbol_exists(htole16 ${ENDIAN_FILE} HAVE_DECL_HTOLE16)
    check_symbol_exists(htobe16 ${ENDIAN_FILE} HAVE_DECL_HTOBE16)
    check_symbol_exists(be16toh ${ENDIAN_FILE} HAVE_DECL_BE16TOH)
    check_symbol_exists(le16toh ${ENDIAN_FILE} HAVE_DECL_LE16TOH)
    check_symbol_exists(htobe32 ${ENDIAN_FILE} HAVE_DECL_HTOBE32)
    check_symbol_exists(htole32 ${ENDIAN_FILE} HAVE_DECL_HTOLE32)
    check_symbol_exists(be32toh ${ENDIAN_FILE} HAVE_DECL_BE32TOH)
    check_symbol_exists(le32toh ${ENDIAN_FILE} HAVE_DECL_LE32TOH)
    check_symbol_exists(htobe64 ${ENDIAN_FILE} HAVE_DECL_HTOBE64)
    check_symbol_exists(htole64 ${ENDIAN_FILE} HAVE_DECL_HTOLE64)
    check_symbol_exists(be64toh ${ENDIAN_FILE} HAVE_DECL_BE64TOH)
    check_symbol_exists(le64toh ${ENDIAN_FILE} HAVE_DECL_LE64TOH)
endif()
# Bitmanip intrinsics
function(check_builtin_exist SYMBOL VARIABLE)
        set(
                SOURCE_FILE
                "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/CheckBuiltinExists.c"
        )
        set(
                CMAKE_CONFIGURABLE_FILE_CONTENT
                "int main(int argc, char** argv) { (void)argv; return ${SYMBOL}(argc); }\n"
        )
        configure_file(
                "${CMAKE_ROOT}/Modules/CMakeConfigurableFile.in"
                "${SOURCE_FILE}"
                @ONLY
        )
        if(NOT CMAKE_REQUIRED_QUIET)
                message(STATUS "Looking for ${SYMBOL}")
        endif()
        try_compile(${VARIABLE}
                ${CMAKE_BINARY_DIR}
                ${SOURCE_FILE}
                OUTPUT_VARIABLE OUTPUT
        )
        if(${VARIABLE})
                if(NOT CMAKE_REQUIRED_QUIET)
                        message(STATUS "Looking for ${SYMBOL} - found")
                endif()
                set(${VARIABLE} 1 CACHE INTERNAL "Have symbol ${SYMBOL}" PARENT_SCOPE)
                file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeOutput.log
                        "Determining if the ${SYMBOL} "
                        "exist passed with the following output:\n"
                        "${OUTPUT}\nFile ${SOURCEFILE}:\n"
                        "${CMAKE_CONFIGURABLE_FILE_CONTENT}\n")
        else()
                if(NOT CMAKE_REQUIRED_QUIET)
                        message(STATUS "Looking for ${SYMBOL} - not found")
                endif()
                set(${VARIABLE} "" CACHE INTERNAL "Have symbol ${SYMBOL}" PARENT_SCOPE)
                file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log
                        "Determining if the ${SYMBOL} "
                        "exist failed with the following output:\n"
                        "${OUTPUT}\nFile ${SOURCEFILE}:\n"
                        "${CMAKE_CONFIGURABLE_FILE_CONTENT}\n")
        endif()
endfunction()
check_builtin_exist(__builtin_clz HAVE_DECL___BUILTIN_CLZ)
check_builtin_exist(__builtin_clzl HAVE_DECL___BUILTIN_CLZL)
check_builtin_exist(__builtin_clzll HAVE_DECL___BUILTIN_CLZLL)
check_builtin_exist(__builtin_popcount HAVE_DECL___BUILTIN_POPCOUNT)
# Optional parts requiring hardware features
macro(add_to_library NAME)
        add_library(${NAME} ${ARGN})
        target_link_libraries(asicseerpool ${NAME})
endmacro()
# SSE4.1
set(SSE41_FLAGS -msse4.1)
string(JOIN " " CMAKE_REQUIRED_FLAGS ${SSE41_FLAGS})
check_cxx_source_compiles("#include <immintrin.h>
        int main() {
                __m128i l = _mm_set1_epi32(0);
                return _mm_extract_epi32(l, 3);
        }
" ENABLE_SSE41)
if(ENABLE_SSE41)
        add_to_library(sse4.1 bitcoin/sha256_sse41.cpp)
        target_compile_definitions(sse4.1 PUBLIC ENABLE_SSE41)
        target_compile_options(sse4.1 PRIVATE ${SSE41_FLAGS})
endif()
# AVX2
set(AVX2_FLAGS -mavx -mavx2)
string(JOIN " " CMAKE_REQUIRED_FLAGS ${AVX2_FLAGS})
check_cxx_source_compiles("#include <immintrin.h>
        int main() {
                __m256i l = _mm256_set1_epi32(0);
                return _mm256_extract_epi32(l, 7);
        }
" ENABLE_AVX2)
if(ENABLE_AVX2)
        add_to_library(avx2 bitcoin/sha256_avx2.cpp)
        target_compile_definitions(avx2 PUBLIC ENABLE_AVX2)
        target_compile_options(avx2 PRIVATE ${AVX2_FLAGS})
endif()
# SHA-NI
set(SHANI_FLAGS -msse4 -msha)
string(JOIN " " CMAKE_REQUIRED_FLAGS ${SHANI_FLAGS})
check_cxx_source_compiles("#include <immintrin.h>
        int main() {
                __m128i i = _mm_set1_epi32(0);
                __m128i j = _mm_set1_epi32(1);
                __m128i k = _mm_set1_epi32(2);
                return _mm_extract_epi32(_mm_sha256rnds2_epu32(i, i, k), 0);
        }
" ENABLE_SHANI)
if(ENABLE_SHANI)
        add_to_library(shani bitcoin/sha256_shani.cpp)
        target_compile_definitions(shani PUBLIC ENABLE_SHANI)
        target_compile_options(shani PRIVATE ${SHANI_FLAGS})
endif()
# Generate the config
configure_file(config.h.cmake.in config.h ESCAPE_QUOTES)
unset(size_t)
include_directories(BEFORE ${CMAKE_BINARY_DIR}/src)  # Ensure config.h is seen
# ------------------------------------------- /config.h generation ------------------------------------------
