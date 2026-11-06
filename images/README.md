# images/

Здесь лежат образы, которые скрипты читают и пишут. В репозитории их нет — они
собираются из твоей прошивки.

| файл | откуда взять |
|---|---|
| `fdl1-dl.bin` | `python tools/extract_pac.py --rar <прошивка>.rar --out images --names FDL` → `python tools/gen_fdl1_dl.py images/fdl1-sign.bin images/fdl1-dl.bin` |
| `fdl2.bin` | `extract_pac.py --names FDL2` → переименовать `lk-fdl2-sign.bin` в `fdl2.bin` |
| `tos-noavb-bsp-bypassed_b.bin` | `python tools/make_tos_noavb.py --slot b --dump tools/dump --out images` |

Ожидаемые хеши — в `../hashes.txt`.

`fdl1-sign.bin` и `lk-fdl2-sign.bin` после извлечения можно удалить, они больше не
нужны.

# images/

Images the scripts read and write. They are not in the repository — build them from
your own firmware.

| file | how |
|---|---|
| `fdl1-dl.bin` | `python tools/extract_pac.py --rar <firmware>.rar --out images --names FDL` → `python tools/gen_fdl1_dl.py images/fdl1-sign.bin images/fdl1-dl.bin` |
| `fdl2.bin` | `extract_pac.py --names FDL2` → rename `lk-fdl2-sign.bin` to `fdl2.bin` |
| `tos-noavb-bsp-bypassed_b.bin` | `python tools/make_tos_noavb.py --slot b --dump tools/dump --out images` |

Expected hashes are in `../hashes.txt`.
