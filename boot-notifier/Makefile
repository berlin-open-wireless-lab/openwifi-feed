#
# Copyright (C) 2013-2014 OpenWrt.org
# Copyright (C) 2016-2017 TU Berlin, Johannes Wegener <mail@johanneswegener.de>
# Copyright (C) 2016-2017 TU Berlin, Julius Schulz-Zander <julius@inet.tu-berlin.de>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=openwifi-boot-notifier
PKG_VERSION:=2016-10-04
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_MAINTAINER:=Johannes Wegener <mail@johanneswegener.de>

include $(INCLUDE_DIR)/package.mk

define Package/openwifi-boot-notifier/Default
  CATEGORY:=Administration
  SECTION:=admin
  SUBMENU:=OpenWiFi
endef

define Package/openwifi-boot-notifier/Default/description
 Notify OpenWiFi when booted
endef

define Package/openwifi-boot-notifier-base
  $(call Package/openwifi-boot-notifier/Default)
  TITLE:=OpenWiFi boot notifier base package
  DEPENDS:=+ip +rpcd +uhttpd-mod-ubus +uhttpd
endef

define Package/openwifi-boot-notifier-base/conffiles
/etc/config/openwifi
endef

define Package/openwifi-boot-notifier-base/description
$(call Package/openwifi-boot-notifier/Default/description)

 Notify OpenWiFi when booted
endef

define Package/openwifi-boot-notifier-base/config
	select BUSYBOX_CONFIG_FEATURE_SHADOWPASSWDS if !shadow-useradd
	select BUSYBOX_CONFIG_MD5SUM
endef

define Package/openwifi-boot-notifier-umdns
  $(call Package/openwifi-boot-notifier/Default)
  TITLE:=Boot Notifier using umDNS
  DEPENDS:=+openwifi-boot-notifier-base +umdns
endef

define Package/openwifi-boot-notifier-umdns/description
$(call Package/openwifi-boot-notifier/Default/description)

 Notify OpenWiFi when booted
endef

define Package/openwifi-boot-notifier-umdns-luci2
  $(call Package/openwifi-boot-notifier/Default)
  TITLE:=Boot Notifier with LuCI v2 Remote Management
  DEPENDS:=+openwifi-boot-notifier-base +umdns +luci2
endef

define Package/openwifi-boot-notifier-umdns-luci2/description
$(call Package/openwifi-boot-notifier/Default/description)

 Notify OpenWiFi when booted
endef

define Package/openwifi-boot-notifier-avahi-luci2
  $(call Package/openwifi-boot-notifier/Default)
  TITLE:=Boot Notifier with LuCI v2 Remote Management using avahi
  DEPENDS:=+openwifi-boot-notifier-base +avahi-utils +luci2
endef

define Package/openwifi-boot-notifier-avahi-luci2/description
$(call Package/openwifi-boot-notifier/Default/description)

 Notify OpenWiFi when booted
endef

define Build/Compile
endef

define Package/openwifi-boot-notifier-base/install
	$(INSTALL_DIR) $(1)/lib/openwifi/
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/etc/config/
	$(INSTALL_DIR) $(1)/sbin/
	$(INSTALL_BIN) ./files/openwifi-boot-notifier.init  $(1)/etc/init.d/openwifi-boot-notifier
	$(INSTALL_BIN) ./files/openwific.sh $(1)/sbin/openwific.sh
	$(INSTALL_BIN) ./files/libopenwifi.sh $(1)/lib/openwifi/openwifi.sh
	$(INSTALL_DATA) ./files/openwifi.config $(1)/etc/config/openwifi
endef

define Package/openwifi-boot-notifier-umdns/install
endef

define Package/openwifi-boot-notifier-umdns-luci2/install
endef

define Package/openwifi-boot-notifier-avahi-luci2/install
endef

define Package/openwifi-boot-notifier-base/postinst
#!/bin/sh
cat > $${IPKG_INSTROOT}/usr/share/rpcd/acl.d/superuser.json << EOF
{
        "superuser": {
                "description": "Super user access role",
                "read": {
                        "ubus": {
                                "*": [ "*" ]
                        },
                        "uci": [ "*" ]
                },
                "write": {
                        "ubus": {
                                "*": [ "*" ]
                        },
                        "uci": [ "*" ]
                }
        }
}
EOF
exit 0
endef

$(eval $(call BuildPackage,openwifi-boot-notifier-base))
$(eval $(call BuildPackage,openwifi-boot-notifier-umdns))
$(eval $(call BuildPackage,openwifi-boot-notifier-umdns-luci2))
$(eval $(call BuildPackage,openwifi-boot-notifier-avahi-luci2))

