# Makefile for DSE bypass tool (embed RTCore64.sys via windres)
# 使用方法: mingw32-make -f Makefile

CXX = g++
CXXFLAGS = -static -mwindows -O2
LDFLAGS = -lntdll -lgdi32 -lcomctl32 -lshell32
RESOURCE_OBJ = resource.o
TARGET = dvr3a.exe
SRC = dvr3a.cpp

# 默认目标
all: $(TARGET)

# 编译资源文件（需要 resource.rc 和 RTCore64.sys 存在）
$(RESOURCE_OBJ): resource.rc RTCore64.sys
	windres resource.rc -o $@

# 链接最终可执行文件
$(TARGET): $(SRC) $(RESOURCE_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# 清理临时文件和目标文件
clean:
	rm -f $(RESOURCE_OBJ) $(TARGET)

# 声明伪目标
.PHONY: all clean
