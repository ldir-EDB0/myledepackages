#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bearDropper
PKG_VERSION:=2016-06-16
PKG_RELEASE:=1
PKG_LICENSE:=GPLv2

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)-$(PKG_RELEASE)

include $(INCLUDE_DIR)/package.mk

define Package/bearDropper
  SECTION:=utils
  CATEGORY:=Utilities
  DEPENDS:=+ipset
  TITLE:=bearDropper - Lightweight ash dropbrute replacement
  PKGARCH:=all
  MAINTAINER:=Kevin Darbyshire-Bryant <kevin@darbyshire-bryant.me.uk>
endef

define Package/beardropper/description
  Rob's ash based replacement for dropBrute.sh
  Using ipset.  Hacky work in progress
endef

define Build/Prepare
endef

define Build/Compile
endef

define Package/bearDropper/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/bearDropper.config $(1)/etc/config/bearDropper
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/bearDropper.sh $(1)/usr/sbin/bearDropper.sh
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/bearDropper.init $(1)/etc/init.d/bearDropper
endef

$(eval $(call BuildPackage,bearDropper))

