PROJECT(ngrok)
CMAKE_MINIMUM_REQUIRED (VERSION 2.8)
ADD_DEFINITIONS( -fno-inline -O0 -g -Wstrict-prototypes -std=gnu99 -Wall)
#ADD_DEFINITIONS( -Os -Wstrict-prototypes -std=gnu99 -Wall)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(LIBEV_LIBRARIES CACHE PATH "Path to the libev library")
set(LIBEV_INCLUDE_DIRS CACHE PATH "Path to the libev include directory")
set(OPENSSL_LIBRARIES CACHE PATH "Path to the openssl library")
set(OPENSSL_INCLUDE_DIRS CACHE PATH "Path to the openssl include directory")
set(JEMALLOC_INCLUDE_DIRS CACHE PATH "Path to the jemalloc include directory")
set(JEMALLOC_LIBRARIES CACHE PATH "Path to the libev library")

#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src)

if ("${LIBEV_INCLUDE_DIRS}" STREQUAL "")
set(LIBEV_LIBRARIES ev)
endif()

if ("${OPENSSL_INCLUDE_DIRS}" STREQUAL "")
set(OPENSSL_LIBRARIES ssl crypto)
endif()

#set(JEMALLOC_INCLUDE_DIRS /opt/projects/source/nodejs/jemalloc)
if (NOT "${JEMALLOC_INCLUDE_DIRS}" STREQUAL "")
include_directories(${JEMALLOC_INCLUDE_DIRS}/include)
link_directories(${JEMALLOC_INCLUDE_DIRS}/lib)
set(JEMALLOC_LIBRARIES jemalloc)
endif()

INCLUDE_DIRECTORIES(${LIBEV_INCLUDE_DIRS} ${PROJECT_SOURCE_DIR}/include)
FILE(GLOB_RECURSE BASIC_SRC ${PROJECT_SOURCE_DIR}/basic/*.c)
FILE(GLOB_RECURSE TUNNEL_SRC ${PROJECT_SOURCE_DIR}/tunnel/*.c)
ADD_LIBRARY(basic STATIC ${BASIC_SRC})

#INCLUDE_DIRECTORIES(${LIBEV_LIBRARIES})

ADD_EXECUTABLE(tunnel ${TUNNEL_SRC})
TARGET_LINK_LIBRARIES(tunnel m ${LIBEV_LIBRARIES} ${OPENSSL_LIBRARIES} basic ${JEMALLOC_LIBRARIES} pthread)

ADD_EXECUTABLE(sslconnect ./tests/sslconnection.c)
TARGET_LINK_LIBRARIES(sslconnect m ${OPENSSL_LIBRARIES})

ADD_EXECUTABLE(khash_test ./tests/khash_test.c)
TARGET_LINK_LIBRARIES(khash_test z rt m ${LIBEV_LIBRARIES} ${OPENSSL_INCLUDE_DIRS} basic pthread ${JEMALLOC_LIBRARIES})
