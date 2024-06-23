cmake_minimum_required(VERSION 3.5)

project(asicseer-pool
        LANGUAGES C CXX
        VERSION 1.4.12
        DESCRIPTION "Fast, C-based, multithreaded mining pool software for Bitcoin Cash"
        HOMEPAGE_URL "https://github.com/cculianu/asicseer-pool")

# Package information
set(PACKAGE_NAME "ASICseer Pool")

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# If ccache is available, then use it.
find_program(CCACHE ccache)
if(CCACHE)
  message(STATUS "Using ccache: ${CCACHE}")
  set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE})
  set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
endif(CCACHE)

# Default to Release configuration
if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release CACHE STRING "Select the configuration for the build" FORCE)
        set(__NO_USER_CMAKE_BUILD_TYPE ON CACHE BOOL "True if the user didn't set a build type on the command line")
endif()

# Add path for custom modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)
include(PackageHelper)

add_subdirectory(src)
