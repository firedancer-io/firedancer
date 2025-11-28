ifdef FD_HAS_ATOMIC
$(call add-hdrs,cJSON.h cJSON_alloc.h)
$(call add-objs,cJSON cJSON_alloc,fd_ballet)
endif