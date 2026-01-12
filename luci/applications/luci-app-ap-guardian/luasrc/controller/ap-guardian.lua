--[[
LuCI controller для AP-Guardian
]]

module("luci.controller.ap-guardian", package.seeall)

function index()
    entry({"admin", "services", "ap-guardian"}, alias("admin", "services", "ap-guardian", "status"), _("AP-Guardian"), 60).index = true
    entry({"admin", "services", "ap-guardian", "status"}, call("action_status"), _("Status"), 1)
    entry({"admin", "services", "ap-guardian", "threats"}, call("action_threats"), _("Threats"), 2)
    entry({"admin", "services", "ap-guardian", "firewall"}, call("action_firewall"), _("Firewall"), 3)
    entry({"admin", "services", "ap-guardian", "settings"}, cbi("ap-guardian/settings"), _("Settings"), 4)
    entry({"admin", "services", "ap-guardian", "logs"}, call("action_logs"), _("Logs"), 5)
end

function action_status()
    local http = require "luci.http"
    local sys = require "luci.sys"
    
    local status = {
        running = false,
        modules = {}
    }
    
    -- Проверка статуса службы
    local pid = sys.exec("pgrep -f 'ap-guardian' | head -1")
    status.running = pid and pid:match("%S+") ~= nil
    
    -- Получение информации о модулях (если доступен API)
    -- В реальной реализации можно использовать сокет или файл статуса
    
    http.prepare_content("application/json")
    http.write_json(status)
end

function action_threats()
    local http = require "luci.http"
    local json = require "luci.jsonc"
    
    -- Чтение угроз из файла или через API
    local threats_file = "/var/run/ap-guardian-threats.json"
    local threats = {}
    
    if nixio.fs.access(threats_file) then
        local content = nixio.fs.readfile(threats_file)
        threats = json.parse(content) or {}
    end
    
    http.prepare_content("application/json")
    http.write_json(threats)
end

function action_firewall()
    local http = require "luci.http"
    local json = require "luci.jsonc"
    
    -- Получение активных блокировок
    local blocks_file = "/var/run/ap-guardian-blocks.json"
    local blocks = {}
    
    if nixio.fs.access(blocks_file) then
        local content = nixio.fs.readfile(blocks_file)
        blocks = json.parse(content) or {}
    end
    
    http.prepare_content("application/json")
    http.write_json(blocks)
end

function action_logs()
    local http = require "luci.http"
    local sys = require "luci.sys"
    
    local log_file = "/var/log/ap-guardian.log"
    local lines = tonumber(http.formvalue("lines") or "50")
    
    local logs = sys.exec(string.format("tail -n %d %s 2>/dev/null", lines, log_file)) or ""
    
    http.prepare_content("text/plain")
    http.write(logs)
end
