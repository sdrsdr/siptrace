project(siptrace)

add_executable(siptrace main.cpp)

install(TARGETS siptrace RUNTIME DESTINATION bin)
