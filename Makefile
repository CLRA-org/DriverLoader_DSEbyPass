# Makefile for DSE bypass tool (embed RTCore64.sys via windres)
# ʹ�÷���: mingw32-make -f Makefile

CXX = g++
CXXFLAGS = -static -mwindows -O2
LDFLAGS = -lntdll -lgdi32 -lcomctl32 -lshell32
RESOURCE_OBJ = resource.o
TARGET = dvr3a.exe
SRC = dvr3a.cpp

# Ĭ��Ŀ�꣨��� UPX ѹ����
all: $(TARGET) upx

# ������Դ�ļ�����Ҫ resource.rc �� RTCore64.sys ���ڣ�
$(RESOURCE_OBJ): resource.rc RTCore64.sys
	windres resource.rc -o $@

# �������տ�ִ���ļ�
$(TARGET): $(SRC) $(RESOURCE_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# ������ʱ�ļ���Ŀ���ļ�
clean:
	rm -f $(RESOURCE_OBJ) $(TARGET)

# UPX ѹ������ UPX installedï¿½
upx: $(TARGET)
	command -v upx >/dev/null 2>&1 && upx --best --lzma $< || echo "UPX not found, skipping compression"

# ����αĿ��
.PHONY: all clean upx
