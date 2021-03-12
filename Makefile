include $(TOPDIR)/rules.mk

PKG_NAME:=UA2F
PKG_VERSION:=2.2

PKG_RELEASE:=4


PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

TARGET_LDFLAGS+=-lmnl -lnetfilter_queue -lipset

include $(INCLUDE_DIR)/package.mk

define Package/ua2f
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Change User-Agent to Fwords
  URL:=https://github.com/Zxilly/UA2F
  DEPENDS:=+libmnl +libnetfilter-queue +iptables-mod-nfqueue +libipset
endef

define Package/ua2f/description
  Change User-agent to Fwords to prevent being checked by Dr.Com.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp ./src/* $(PKG_BUILD_DIR)
	$(Build/Patch)
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -o $(PKG_BUILD_DIR)/ua2f.o -c $(PKG_BUILD_DIR)/ua2f.c
	$(TARGET_CC) $(TARGET_LDFLAGS) -o $(PKG_BUILD_DIR)/$1 $(PKG_BUILD_DIR)/ua2f.o
endef

define Package/ua2f/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ua2f $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./init/ua2f $(1)/etc/init.d/ua2f
endef

$(eval $(call BuildPackage,ua2f))
