include $(TOPDIR)/rules.mk

PKG_NAME:=UA2F
PKG_VERSION:=3.7
PKG_RELEASE:=12

PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILE:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/ua2f
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Change User-Agent to Fwords
  URL:=https://github.com/Zxilly/UA2F
  DEPENDS:=+iptables-mod-nfqueue +libipset +libnetfilter-conntrack +libnetfilter-queue
endef

define Package/ua2f/description
  Change User-agent to Fwords to prevent being checked by Dr.Com.
endef

EXTRA_LDFLAGS += -lmnl -lnetfilter_queue -lipset

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) $(EXTRA_LDFLAGS) \
		$(PKG_BUILD_DIR)/ua2f.c -o $(PKG_BUILD_DIR)/ua2f
endef

define Package/ua2f/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ua2f $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./init/ua2f $(1)/etc/init.d/ua2f
endef

$(eval $(call BuildPackage,ua2f))
