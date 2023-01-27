target_sources(cvss 
    PRIVATE cvss_3_1.cpp 
    PUBLIC FILE_SET HEADERS 
    BASE_DIRS ${PROJECT_SOURCE_DIR}
    FILES cvss_3_1.h)
