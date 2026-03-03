$(info [EXTERNAL] BR2_EXTERNAL=$(BR2_EXTERNAL))

# Buildroot external tree glue for sb_enema
# Automatically include any package .mk files if added later.
include $(sort $(wildcard $(BR2_EXTERNAL_SB_ENEMA_PATH)/package/*/*.mk))
