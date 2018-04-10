find_path(RTMP_INCLUDE_DIR librtmp/rtmp.h)
find_library(RTMP_LIBRARIES rtmp)

mark_as_advanced(RTMP_INCLUDE_DIR RTMP_LIBRARIES)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBRTMP
  DEFAULT_MSG RTMP_LIBRARIES RTMP_INCLUDE_DIR
)
