#
# Copyright (C) 2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pping
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/pollere/pping
PKG_SOURCE_DATE:=2017-05-23
PKG_SOURCE_VERSION:=881c665419c215e21e691fcbb582fe8352534ce5

include $(INCLUDE_DIR)/package.mk

define Package/pping
  SECTION:=utils
  CATEGORY:=Network
  TITLE:=Pollere pping
  DEPENDS:=
endef

define Package/pping/description
  This is a set of scripts that we use to measure (and improve) latency in home
  routers (and everywhere else!)
endef

define Build/Compile
endef

define Package/pping/install
	$(INSTALL_DIR) $(1)/usr/lib/CeroWrtScripts
	$(CP) $(PKG_BUILD_DIR)/*.sh $(1)/usr/lib/CeroWrtScripts/
endef

$(eval $(call BuildPackage,pping))
