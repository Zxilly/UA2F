include $(TOPDIR)/rules.mk

PKG_NAME:=UA2F
PKG_VERSION:=3.10
PKG_RELEASE:=1

PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILE:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/ua2f
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Change User-Agent to Fwords on the fly.
  URL:=https://github.com/Zxilly/UA2F
  DEPENDS:=+ipset +iptables-mod-conntrack-extra +iptables-mod-nfqueue \
    +libnetfilter-conntrack +libnetfilter-queue
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

	$(INSTALL_DIR) $(1)/etc/config $(1)/etc/init.d $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/ua2f.config $(1)/etc/config/ua2f
	$(INSTALL_BIN) ./files/ua2f.init $(1)/etc/init.d/ua2f
	$(INSTALL_BIN) ./files/ua2f.uci $(1)/etc/uci-defaults/80-ua2f
endef

define Package/ua2f/postinst
#!/bin/sh

# check if we are on real system
[ -n "$${IPKG_INSTROOT}" ] || {
	(. /etc/uci-defaults/80-ua2f) && rm -f /etc/uci-defaults/80-ua2f
	exit 0
}
endef

$(eval $(call BuildPackage,ua2f))
