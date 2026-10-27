vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO Atlas-Authorization/atlas-cpp
    REF "v${VERSION}"
    SHA512 0
    HEAD_REF main
)
set(VCPKG_BUILD_TYPE release)
vcpkg_cmake_configure(SOURCE_PATH "${SOURCE_PATH}" OPTIONS -DBUILD_TESTING=OFF)
vcpkg_cmake_install()
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
