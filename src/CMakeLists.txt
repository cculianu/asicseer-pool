# ZMQ
find_package(ZeroMQ 4.1.5 REQUIRED)

# Jansson
add_subdirectory(jansson-2.10)
include_directories(AFTER ${CMAKE_BINARY_DIR}/src/jansson-2.10/include ${CMAKE_SOURCE_DIR}/src/jansson-2.10/src)

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

# Yasm
set(EXTRA_OBJS "")
# TODO: Auto-detect these based on current build machine CPU
option(USE_AVX2 "Use avx2 assembly instructions for sha256" ON)
option(USE_AVX1 "Use avx1 assembly instructions for sha256" OFF)
option(USE_SSE4 "Use sse4 assembly instructions for sha256" OFF)
function(add_yasm_custom_command VAR BASENAME)
    set(VAR_VAL "${${VAR}}")
    if(VAR_VAL)
        find_program(YASM_EXE NAMES yasm)
        if (YASM_EXE STREQUAL "YASM_EXE-NOTFOUND")
            message(FATAL_ERROR "The `yasm` executable was not found. Try installing it or re-run cmake with -D${VAR}=OFF")
        endif()
        set(CMAKE_INCLUDE_CURRENT_DIR ON)
        # TODO: Support non-Linux here such as macOS, etc.
        add_custom_command(OUTPUT "${BASENAME}.o"
            COMMAND ${YASM_EXE}
            ARGS -f x64 -f elf64 -X gnu -g dwarf2 -D LINUX -o ${BASENAME}.o "${CMAKE_CURRENT_SOURCE_DIR}/sha256_code_release/${BASENAME}.asm")
        set(EXTRA_OBJS ${EXTRA_OBJS} ${BASENAME}.o PARENT_SCOPE)
    endif()
endfunction()
add_yasm_custom_command("USE_AVX2" "sha256_avx2_rorx2")
add_yasm_custom_command("USE_AVX1" "sha256_avx1")
add_yasm_custom_command("USE_SSE4" "sha256_sse4")

add_library(asicseerpool libasicseerpool.c libasicseerpool_cxx.cpp libasicseerpool.h sha2.c sha2.h cashaddr.c cashaddr.h
                         ${EXTRA_OBJS})

add_executable(asicseer-pool asicseer-pool.c asicseer-pool.h generator.c generator.h bitcoin.c bitcoin.h
                             stratifier.c stratifier.h connector.c connector.h uthash.h utlist.h donation.h empty.cpp)
target_link_libraries(asicseer-pool ${LIBS} ZeroMQ::zmq)

add_executable(asicseer-pmsg asicseer-pmsg.c empty.cpp)
target_link_libraries(asicseer-pmsg ${LIBS})

add_executable(notifier notifier.c empty.cpp)
target_link_libraries(notifier ${LIBS})

add_executable(summariser summariser.c empty.cpp)
target_link_libraries(summariser ${LIBS})

option(ENABLE_CKDB "Enable ckdb" OFF)
if(ENABLE_CKDB)
    add_executable(asicseer-db asicseer-db.c ckdb_cmd.c ckdb_data.c ckdb_dbio.c ckdb_btc.c ckdb_crypt.c
                               asicseer-db.h klist.c ktree.c klist.h ktree.h empty.cpp)
    target_link_libraries(asicseer-db ${LIBS})
    set(USE_ASICSEER_DB 1)
endif()

# ------------------------------------------- config.h generation -------------------------------------------
# This generates config.h which provides numerous defines about the state of the platform we are building on.
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckCSourceCompiles)

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
check_include_files("ctype.h" HAVE_CTYPE_H)
check_include_files("dirent.h" HAVE_DIRENT_H)
check_include_files("dlfcn.h" HAVE_DLFCN_H)
check_include_files("endian.h" HAVE_ENDIAN_H)
check_include_files("errno.h" HAVE_ERRNO_H)
check_include_files("fcntl.h" HAVE_FCNTL_H)
check_include_files("fenv.h" HAVE_FENV_H)
check_include_files("getopt.h" HAVE_GETOPT_H)
check_include_files("grp.h" HAVE_GRP_H)
check_include_files("gsl/gsl_cdf.h" HAVE_GSL_GSL_CDF_H)
check_include_files("gsl/gsl_math.h" HAVE_GSL_GSL_MATH_H)
check_include_files("inttypes.h" HAVE_INTTYPES_H)
check_include_files("libpq-fe.h" HAVE_LIBPQ_FE_H)
check_include_files("linux/un.h" HAVE_LINUX_UN_H)
check_include_files("math.h" HAVE_MATH_H)
check_include_files("memory.h" HAVE_MEMORY_H)
check_include_files("netdb.h" HAVE_NETDB_H)
check_include_files("netinet/in.h" HAVE_NETINET_IN_H)
check_include_files("netinet/tcp.h" HAVE_NETINET_TCP_H)
check_include_files("openssl/hmac.h" HAVE_OPENSSL_HMAC_H)
check_include_files("openssl/x509.h" HAVE_OPENSSL_X509_H)
check_include_files("postgresql/libpq-fe.h" HAVE_POSTGRESQL_LIBPQ_FE_H)
check_include_files("sys/endian.h" HAVE_SYS_ENDIAN_H)
check_include_files("sys/epoll.h" HAVE_SYS_EPOLL_H)
check_include_files("sys/ioctl.h" HAVE_SYS_IOCTL_H)
check_include_files("sys/poll.h" HAVE_SYS_POLL_H)
check_include_files("sys/prctl.h" HAVE_SYS_PRCTL_H)
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
# Generate the config
configure_file(config.h.cmake.in config.h ESCAPE_QUOTES)
unset(size_t)
include_directories(BEFORE ${CMAKE_BINARY_DIR}/src)  # Ensure config.h is seen
# ------------------------------------------- /config.h generation ------------------------------------------
