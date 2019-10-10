#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=log2drop
PKG_VERSION:=2019-10-06
PKG_RELEASE:=1
PKG_LICENSE:=GPLv2

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)-$(PKG_RELEASE)

include $(INCLUDE_DIR)/package.mk

define Package/log2drop
  SECTION:=utils
  CATEGORY:=Utilities
  DEPENDS:=+ipset
  TITLE:=log2drop - Lightweight ash dropbrute replacement
  PKGARCH:=all
  MAINTAINER:=Kevin Darbyshire-Bryant <kevin@darbyshire-bryant.me.uk>
endef

define Package/log2drop/description
  A cut down version of Rob's bearDropper that uses ipsets
  instead of individual iptables rules.  Also supports IPv6.
  Needs a slightly hacked dropbear that reports IP addresses
  in auth failure messages.
endef

define Build/Prepare
endef

define Build/Compile
endef

define Package/log2drop/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/log2drop.config $(1)/etc/config/log2drop
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/log2drop.sh $(1)/usr/sbin/log2drop.sh
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/log2drop.init $(1)/etc/init.d/log2drop
endef

$(eval $(call BuildPackage,log2drop))

