#!/system/bin/sh
# Fix the settings key written with stray spaces, then enable Zygisk properly.
magisk --sqlite "DELETE FROM settings WHERE key LIKE '%zygisk%'"
magisk --sqlite "REPLACE INTO settings (key,value) VALUES('zygisk',1)"
magisk --sqlite "select * from settings"
