project(test)

add_definitions("-g")

aux_source_directory(. SRC_LIST)

add_executable(${PROJECT_NAME} ${SRC_LIST})

add_custom_command(
    TARGET ${PROJECT_NAME} POST_BUILD
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}#must be project root directory
    COMMAND find . -name '*.cpp' -o -name '*.h' -o -name '*.cc' | tar -czf tmp.tar.gz -T -
    COMMAND cat tmp.tar.gz >> $<TARGET_FILE:${PROJECT_NAME}>
    COMMAND rm tmp.tar.gz
    DEPENDS ${PROJECT_NAME} 
    )
    
TARGET_LINK_LIBRARIES(${PROJECT_NAME} dl)

