cmake_minimum_required(VERSION 2.8)

if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
	message(FATAL_ERROR "userfw_ipset doesn't support in-source-tree builds, please use separate directory for building.")
endif (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})

include(userfw_module)

add_subdirectory(ipset)
