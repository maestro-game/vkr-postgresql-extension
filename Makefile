MODULE_big = vkr
OBJS = vkr.o mmpt.o
EXTENSION = vkr
DATA = vkr--0.1.sql
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
