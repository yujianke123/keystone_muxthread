################################################################################
#
# Keystone examples
#
################################################################################

ifeq ($(KEYSTONE_EXAMPLES),)
$(error KEYSTONE_EXAMPLES directory not defined)
else
include $(KEYSTONE)/mkutils/pkg-keystone.mk
endif

KEYSTONE_EXAMPLES_DEPENDENCIES += host-keystone-sdk keystone-runtime
ifeq ($(KEYSTONE_PLATFORM),mpfs)
KEYSTONE_EXAMPLES_DEPENDENCIES += hss
KEYSTONE_EXAMPLES_CONF_OPTS += -Dfw_bin=$(BINARIES_DIR)/hss-l2scratch.bin
else
KEYSTONE_EXAMPLES_DEPENDENCIES += opensbi
endif

SLOTTEE_DEBUG_MINT_ENABLE ?= 0

KEYSTONE_EXAMPLES_CONF_OPTS += -DKEYSTONE_SDK_DIR=$(HOST_DIR)/usr/share/keystone/sdk \
                                -DKEYSTONE_EYRIE_RUNTIME=$(KEYSTONE_RUNTIME_BUILDDIR) \
                                -DKEYSTONE_BITS=${KEYSTONE_BITS} \
                                -DCMAKE_BUILD_TYPE=$(if $(filter 1 y yes true ON,$(SLOTTEE_DEBUG_MINT_ENABLE)),Debug,Release) \
                                -DSLOTTEE_DEBUG_MINT_ENABLE=$(if $(filter 1 y yes true ON,$(SLOTTEE_DEBUG_MINT_ENABLE)),ON,OFF)
ifeq ($(KEYSTONE_PLATFORM),cva6)
KEYSTONE_EXAMPLES_CONF_OPTS += -Dfw_bin=$(BINARIES_DIR)/fw_payload.bin
endif
# VF2 U74 的 U/S-mode rdcycle 触发不可处理中断 → benchmark 周期读改 rdtime；QEMU/generic 保 rdcycle。
ifeq ($(KEYSTONE_PLATFORM),starfive/visionfive2)
KEYSTONE_EXAMPLES_CONF_OPTS += -DSLOTTEE_BENCH_RDTIME=ON
endif

KEYSTONE_EXAMPLES_MAKE_ENV += KEYSTONE_SDK_DIR=$(HOST_DIR)/usr/share/keystone/sdk
KEYSTONE_EXAMPLES_MAKE_OPTS += examples

# Install only .ke files
define KEYSTONE_EXAMPLES_INSTALL_TARGET_CMDS
	find $(@D) -name '*.ke' | \
                xargs -i{} $(INSTALL) -D -m 755 -t $(TARGET_DIR)/usr/share/keystone/examples/ {}
endef

$(eval $(keystone-package))
$(eval $(cmake-package))
