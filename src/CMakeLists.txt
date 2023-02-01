target_sources(cvss 
    PRIVATE cvss.cpp cvss_3.cpp cvss_3_1.cpp 
    PUBLIC FILE_SET HEADERS 
    BASE_DIRS ${PROJECT_SOURCE_DIR}
    FILES cvss.h cvss_3.h cvss_3_1.h)
