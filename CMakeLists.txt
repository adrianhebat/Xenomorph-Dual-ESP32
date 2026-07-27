cmake_minimum_required(VERSION 3.5)

# TAMBAHKAN BARIS INI:
set(EXTRA_COMPONENT_DIRS components/xenomorph_uart)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(xenomorph-muscle)