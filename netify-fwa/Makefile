#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=netify-fwa
PKG_SOURCE_VERSION:=7849f25d32446c2a63804e551c847d29498f6bc1
PKG_VERSION:=0.99
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://gitlab.com/ldir/netify-fwa.git
PKG_MIRROR_HASH:=101e8ccbeab7acc85e94ab1615f053745e75542199eba8b9cd8628fd2fbf80ea

PKG_LICENSE:=GPLv3

include $(INCLUDE_DIR)/package.mk

define Package/netify-fwa
  SECTION:=Network
  DEPENDS:=+netifyd +python3-email +python3-ctypes +python3-codecs
  TITLE:=netify-fwa - Netify Firewall Agent
  PKGARCH:=all
endef

define Package/netify-fwa/description
  netify firewall agent - using python3
endef

define Package/netify-fwa/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/log2drop.config $(1)/etc/config/log2drop
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/log2drop.sh $(1)/usr/sbin/log2drop.sh
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/log2drop.init $(1)/etc/init.d/log2drop
endef

$(eval $(call BuildPackage,netify-fwa))

