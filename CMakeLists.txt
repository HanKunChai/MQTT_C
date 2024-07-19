cmake_minimum_required(VERSION 3.10)  
  
# 设置项目名称和版本  
project(MQTT_Project VERSION 1.0)  
  
# 设置C标准  
set(CMAKE_C_STANDARD 99)  
# set(CMAKE_C_STANDARD_REQUIRED True)  
  
# 添加包含目录，以便编译器可以找到头文件  
include_directories(src/includes)  
  
# 递归地添加src目录下的所有.c文件到变量SOURCES中  
file(GLOB_RECURSE SOURCES src/*.c src/packets/*.c src/utils/*.c src/component/*.c)  
  
# 注意：这里我们包含了src/headers/*.c，但通常headers目录用于存放头文件  
# 如果src/headers目录下确实包含源文件，请确认这是您想要的；否则，请调整目录结构或GLOB_RECURSE表达式  
  
# 添加可执行文件  
add_executable(mqtt_test src/main_test.c ${SOURCES})  
  
# 如果您的项目依赖于外部库，可以在这里使用find_package和target_link_libraries来查找和链接这些库  
# 例如：  
# find_package(OpenSSL REQUIRED)  
# target_link_libraries(mqtt_test OpenSSL::SSL OpenSSL::Crypto)