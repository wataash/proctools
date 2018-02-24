cmake_minimum_required(VERSION 3.9)
project(proctools)

set(CMAKE_VERBOSE_MAKEFILE on)

set(SRCS_COMMON
        proctools/fmt.c
        proctools/proctools.c
        proctools/proctools.h
        )

add_executable(pkill ${SRCS_COMMON} pkill/pkill.c)
add_executable(pgrep ${SRCS_COMMON} pgrep/pgrep.c)
add_executable(pfind ${SRCS_COMMON} pfind/pfind.c pfind/pfind.h)
