project(siptrace)

add_executable(siptrace main.c eth.c)
target_link_libraries(siptrace pcap)
#install(TARGETS siptrace RUNTIME DESTINATION bin)
