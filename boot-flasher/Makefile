#
# Copyright (C) 2013-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=openwifi-boot-flasher
PKG_VERSION:=2016-10-05
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_MAINTAINER:=Johannes Wegener <mail@johanneswegener.de>

include $(INCLUDE_DIR)/package.mk

define Package/openwifi-boot-flasher/Default
  SECTION:=utils
  CATEGORY:=OpenWifi
endef

define Package/openwifi-boot-flasher/Default/description
 Flash Device on boot and then do kexec afterwards
endef

define Package/openwifi-boot-flasher
  $(call Package/openwifi-boot-flasher/Default)
  TITLE:=Boot Flasher Package
  DEPENDS:=+ip +rpcd +uhttpd-mod-ubus +umdns +shadow-useradd +uhttpd +rpcd-mod-iwinfo +rpcd-mod-file +libubox +libubus +openwifi-boot-notifier-umdns +kexec-tools +sha256sum
endef

define Build/Compile
endef

define Package/openwifi-boot-flasher/install
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/openwifi-boot-flasher.init  $(1)/etc/init.d/openwifi-boot-flasher
endef

$(eval $(call BuildPackage,openwifi-boot-flasher))
