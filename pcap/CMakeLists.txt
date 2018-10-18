cmake_minimum_required(VERSION 3.6)

project(Poc)

# cmake -DCMAKE_BUILD_TYPE=Release ..
# make VERBOSE=1

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)


#3rd party
set (PCAP_HOME "~/toolbox/libpcap-0.9.4")

#common
set(CMAKE_CXX_STANDARD 14)

#buld defined
if(NOT CMAKE_DEBUG_POSTFIX)
  set(CMAKE_DEBUG_POSTFIX D)
endif()

if( NOT CMAKE_BUILD_TYPE )
  set( CMAKE_BUILD_TYPE Debug CACHE STRING
       "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
       FORCE )
endif()
message ("CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")

if(CMAKE_BUILD_TYPE MATCHES Release)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_RELASE} -Wall -Werror -O3")
  set(POC_TARGET poc) 
else()
  set(POC_TARGET pocD)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Werror -g3 -O0")
endif()

message ("CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS}")

include_directories(${PCAP_HOME} include)
message ("include_directories=${include_directories}")
link_directories(${PCAP_HOME})

set(POC_SCR src/main.cpp src/pcap_ip.cpp)

add_executable(${POC_TARGET} ${POC_SCR})
target_link_libraries(${POC_TARGET} pcap)



# UNIX, WIN32, WINRT, CYGWIN, APPLE are environment variables as flags set by default system
if(UNIX)
    message("This is a ${CMAKE_SYSTEM_NAME} system")
elseif(WIN32)
    message("This is a Windows System")
endif()

# or use MATCHES to see if actual system name
# Darwin is Apple's system name
if(${CMAKE_SYSTEM_NAME} MATCHES Darwin)
    message("This is a ${CMAKE_SYSTEM_NAME} system")
elseif(${CMAKE_SYSTEM_NAME} MATCHES Windows)
    message("This is a Windows System")
endif()



