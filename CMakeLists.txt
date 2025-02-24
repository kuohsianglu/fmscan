cmake_minimum_required(VERSION 2.6)

PROJECT(fmscan C)
INCLUDE(GNUInstallDirs)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror -Wmissing-declarations --pedantic)

SET(LIBS ubox ubus bluetooth)

ADD_EXECUTABLE(fmscan main.c ubus.c)
TARGET_LINK_LIBRARIES(fmscan ${LIBS})
INSTALL(TARGETS fmscan
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
