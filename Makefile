-include Makefile.env

SUBDIRS = src
TARGET = tiny_nettools

all: subdirs $(TARGET)
 
subdirs: $(SUBDIRS)
	@if [ ! -d $(BUILD_DIR) ]; then mkdir -p $(BUILD_DIR); fi;
	@if [ ! -d $(DEP_DIR) ]; then mkdir -p $(DEP_DIR); fi;
	@if [ ! -d $(OBJ_DIR) ]; then mkdir -p $(OBJ_DIR); fi;
	@for dir in $(SUBDIRS);do $(MAKE) -C $$dir all||exit 1;done
	
$(TARGET): $(OBJS)
	$(CC) -o $(BUILD_DIR)/$(TARGET) $(OBJS) -L$(LIB_DIR) $(LFLAGS)

OBJS = $(wildcard $(OBJ_DIR)/*.o)

clean:
	rm -rf $(DEP_DIR)/*.d
	rm -rf $(OBJ_DIR)/*.o
	rm -rf $(BUILD_DIR)/$(TARGET)

.PHONY: all clean
