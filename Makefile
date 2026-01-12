include $(TOPDIR)/rules.mk

PKG_NAME:=ap-guardian
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=AP-Guardian Team
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/ap-guardian
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AP-Guardian - Active Network Protection System
  DEPENDS:=+python3 +python3-scapy +iptables +arptables
  PKGARCH:=all
endef

define Package/ap-guardian/description
  Система активной сетевой защиты для автоматического обнаружения 
  и блокировки кибератак уровня L2/L3 в общедоступных Wi-Fi сетях 
  на базе маршрутизаторов с OpenWrt.
endef

define Build/Compile
	# Копирование исходных файлов
	$(CP) -r $(PKG_BUILD_DIR)/src $(PKG_BUILD_DIR)/files/usr/lib/ap-guardian/
	# Создание символической ссылки для запуска
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/files/usr/bin
	$(LN) -s /usr/lib/ap-guardian/src/main.py $(PKG_BUILD_DIR)/files/usr/bin/ap-guardian
endef

define Package/ap-guardian/install
	# Установка Python модулей
	$(INSTALL_DIR) $(1)/usr/lib/ap-guardian
	$(CP) -r $(PKG_BUILD_DIR)/src $(1)/usr/lib/ap-guardian/
	
	# Установка скриптов
	$(INSTALL_DIR) $(1)/usr/lib/ap-guardian
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/usr/lib/ap-guardian/uci_to_json.py $(1)/usr/lib/ap-guardian/
	
	# Установка бинарных файлов
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/usr/bin/ap-guardian $(1)/usr/bin/
	
	# Установка конфигурационных файлов
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/files/etc/config/ap-guardian $(1)/etc/config/
	
	# Установка init скрипта
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/ap-guardian $(1)/etc/init.d/
	
	# Создание директорий
	$(INSTALL_DIR) $(1)/etc/ap-guardian
	$(INSTALL_DIR) $(1)/var/log
endef

$(eval $(call BuildPackage,ap-guardian))
