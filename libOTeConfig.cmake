
####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was Config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

####################################################################################

set(ENABLE_SIMPLESTOT     ON)
set(ENABLE_SIMPLESTOT_ASM ON)
set(ENABLE_MR             ON)
set(ENABLE_MR_KYBER       ON)
set(ENABLE_NP             ON)
set(ENABLE_KOS            ON)
set(ENABLE_IKNP           ON)
set(ENABLE_SILENTOT       ON)
set(ENABLE_DELTA_KOS      ON)
set(ENABLE_DELTA_IKNP     ON)
set(ENABLE_OOS            ON)
set(ENABLE_KKRT           ON)
set(ENABLE_RR             ON)
set(ENABLE_AKN            ON)
set(ENABLE_SILENT_VOLE    ON)
find_package(cryptoTools REQUIRED HINTS "${CMAKE_CURRENT_LIST_DIR}/.." ${CMAKE_CURRENT_LIST_DIR})


include("${CMAKE_CURRENT_LIST_DIR}/libOTeTargets.cmake")

OC_getAllLinkedLibraries(oc::libOTe libOTe_LIBRARIES libOTe_INCLUDE_DIRS)
OC_getAllLinkedLibraries(oc::libOTe_Tests libOTe_Tests_LIBRARIES libOTe_Tests_INCLUDE_DIRS)

set(libOTe_LIB ${libOTe_LIBRARIES})
set(libOTe_INC ${libOTe_INCLUDE_DIRS})
set(libOTe_Tests_LIB ${libOTe_Tests_LIBRARIES})
set(libOTe_Tests_INC ${libOTe_Tests_INCLUDE_DIRS})
