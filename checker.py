#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Проверка публичных VLESS-конфигов на живость.

Три ступени, каждая отсеивает дешёвым способом до того, как включится дорогая:
  1. TCP-коннект на host:port     -- бесплатно, срезает примерно половину
  2. рукопожатие + cdn-cgi/trace  -- нода реально поднимает тоннель
  3. прокачка 256 КБ              -- через тоннель идут байты, а не только SYN

Третья ступень нужна отдельно: узел может ответить на рукопожатие и не
пропустить ни байта полезного трафика. Пинг и скорость тут НЕ меряем -- они
измерялись бы от раннера, а не от того, кто потом пойдёт через ноду.
"""
import argparse
import base64
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# Ревизия 29.10 (аудит свежести источников): главная причина просадки живых
# нод -- не объём пула (172k ключей, как и было), а его возраст. Замер по
# atom-фидам: sevcator/5ubscrpt10n не коммитит с 17.08 (73 дня) -- его 95k
# ключей заморожены и почти все мертвы, файл 104 МБ качается зря;
# bugbounted мёртв с 2023-07 (в пул лёгло +1768 трёхлетних ключей);
# nikita29a/FreeProxyList жив, но ротация ушла с mirror/12.txt на 1.txt
# (1.txt побайтово совпадает с шардом 1 -- источник целиком бесполезен);
# mheidari98/.proxy -- побайтовая копия шарда 10 (7.3 МБ мимо кассы).
# Апстрим AvenCores на GitLab жив (автокоммит ежедневно), у его
# githubmirror/2.txt 405k vless против 109k у замершего зеркального 2.txt --
# шард 2 берём напрямую с GitLab.
#
# Четыре источника умерли в середине октября (выяснено клонами и редиректами,
# 29.10): Epodonios/v2ray-configs и ebrasha/free-v2ray-public-list -- аккаунты
# удалены целиком (нашедшиеся зеркала дают marg 8-36 -- контент уже в пуле);
# LeilaoMi жив, но output/all.txt переименован в global.txt и сам деградировал
# до 76 нод (было ~+2.6k); whoahaow/rjsxrd отключил raw-дампы апстримом
# (теперь за feature-флагами) -- былые +24k уникальных невозвратны.
BASE = ("https://raw.githubusercontent.com/pog7x/vpn-configs/master/"
        "githubmirror/%d.txt")
# Замерший шард 2 берём с живого апстрима (см. шапку).
BASE_GITLAB = ("https://gitlab.com/avencores/goida-vpn-configs/-/raw/main/"
               "githubmirror/2.txt")
# AvenCores -- основной источник, ~100k конфигов. Он же надмножество списка,
# который тянет сам сервер, так что отдельно проверять серверный смысла нет.
#
# Остальные добавлены после того, как отпал довод против слабых источников:
# пока сервер сканировал сам, они крали у него слоты и роняли выхлоп (замер
# 23.08: 712 находок в сутки -> 451). Теперь наружу уезжают только
# проверенные ноды, и слабый список стоит лишь минуты времени раннера.
# Замер их живости: 1.75% против 6.25% у основного -- около +50 живых нод.
EXTRA = [
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vless",
    # Пополнение 14.09: замер прироста уникальных (host:port:uid) поверх
    # старого пула в 102k. Сырые пулы дают объём: 0xRadikal +732,
    # VestraNet +417 -- при той же живости 2-6% это ещё ~+100-200 находок.
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs"
    "/main/protocols/vless.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes"
    "/main/subscriptions/mix-normal.txt",
    # Проверенный у источника: сами гоняли трафик через xray/sing-box,
    # обновляют почасово. Объём мал, но брака почти нет,
    # в отличие от 1.75-6.25% у сырых списков. (v2go, Au1rxx, CaptchaQ
    # вырезаны 29.10: marg 2-9, весь их контент уже в пуле; 0xRadikal
    # verified тоже -- marg упал с 1 до 0.)
    # Пополнение 15.09 (волна 2): FastNodes/curated даёт объём и свежесть
    # (обновление каждые 49 мин, замер 29.10), Pulse -- 2 ч.
    # top/verified вырезаны 29.10: marg 0, дублируют curated.
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/curated.txt",
    "https://raw.githubusercontent.com/drmikecrypto/PulseConfigs"
    "/main/protocols/vless.txt",
    "https://raw.githubusercontent.com/cybersecplayground/V2Hive"
    "/main/by-protocol/all_vless.txt",
    # РФ-специфичные: маленькие, но отобраны под работу из России
    # (igareck 75-20% свежести, aviaRU 75%) -- выживают за RU-DPI лучше
    # прочих, дают более живой процент с домашних адресов. Держим даже при
    # нулевом marg: на замер день контент совпал с пулом, но это единственные
    # кураторки под RU-DPI, и их живость мерится не объёмом.
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia"
    "/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia"
    "/main/ru_configs.txt",
    # Пополнение 25.09: третий слой -- подписочные эндпоинты, не TG и не
    # перепродажа. morpheusadam сам ищет сабы по GitHub (harvest.py с
    # --tree), диалит каждую ссылку перед публикацией, крон 12:37 UTC.
    # VOID -- РФ-кураторка, проверяет своим xray, обновление раз в час.
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config"
    "/main/subs/bundles/vless.txt",
    "https://raw.githubusercontent.com/VOID-Anonymity/V.O.I.D-VPN_Bypass"
    "/main/url_work.txt",
    # Xer0x-vless-hub сам валидирует ноды с флагами стран, обновляется
    # ежедневно; объём мал, брака почти нет. (barry-far вырезан 29.10:
    # marg 0 -- весь его слиток уже в шардах и у kilroy98.)
    "https://raw.githubusercontent.com/Realmec21/Xer0x-vless-hub"
    "/main/subscriptions/all.txt",
    # 4Diana -- рекомендация NiREvil/vless; 3inker -- русский
    # коллектор-проверщик, ветка not-RU; Farid-Karimi -- иранский срез.
    # Все живы (коммиты 29.10).
    "https://raw.githubusercontent.com/EEvanescence/4Diana"
    "/main/By-protocol/vless.txt",
    "https://raw.githubusercontent.com/3inker/v2ray-subscription"
    "/main/subs/all_not_ru.txt",
    "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector"
    "/main/vless_iran.txt",
    # kilroy98 -- живой наследник soroushmirzaei, своя ферма из 837 каналов
    # + разбивка по странам; коммит 29.10 (7 ч). Второй живой мега-слой
    # после ухода sevcator: +33k уникальных поверх пула (замер 29.10).
    "https://raw.githubusercontent.com/kilroy98/telegram-configs-collector3"
    "/main/protocols/vless",
    # Пополнение 29.10 (аудит + вылазка субагентов). Замер marg поверх пула
    # в 171.7k ключей; свежесть по atom-фидам. Отличие от прежних волн:
    # "проверенные" источники (валидируют ноды у себя) свой ресурс исчерпали
    # -- их сырьё уже в пуле, marg 0-1 у всех проверенных. Прирост остался
    # только у RU-агрегаторов, которых нет в чужих дампах.
    "https://raw.githubusercontent.com/muks999/Clash-Vless-convert"
    "/main/vless_lite.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn"
    "/main/configs/32.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn"
    "/main/configs/1.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn"
    "/main/configs/24.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn"
    "/main/configs/26.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn"
    "/main/configs/28.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn"
    "/main/configs/33.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn"
    "/main/configs/8.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn"
    "/main/configs/2.txt",
    # DarkRoyalty -- TG-агрегатор; servers.json -- JSON-массив ссылок,
    # fetch_all выдирает vless регэкспом. Сам дамп (githubmirror/*.txt,
    # 405k vless) уже покрыт пулом, прирост даёт только свежий servers.json.
    "https://raw.githubusercontent.com/DarkRoyalty/shnajder-vpn-configs"
    "/main/servers.json",
    # Волна 4 (29.10, вторая вылазка субагентов): коллекторы со СВОИМИ
    # TG-каналами вне мейнстрима -- единственный класс, дающий прирост
    # (мейнстрим-коллекторы поглощены пулом на 97-100%, marg 0-25).
    # Darmioniks: автокоммиты 4-6 в день, построчный текст, +6199 уникальных.
    # TheCrowCreature: ~4 коммита в день, файл с расширением .html, но это
    # чистый построчный vless без тегов (проверено), +4039; пересечение
    # находок между ними 66 нод -- берутся вместе.
    "https://raw.githubusercontent.com/Darmioniks/proxy-and-vless-collector"
    "/main/vless.txt",
    "https://raw.githubusercontent.com/TheCrowCreature/v2rayExtractor"
    "/main/vless.html",
    # Волна 5 (30.10, вторая вылазка: гисты/кодопоиск, GitLab/Codeberg/Gitee,
    # TG-каналы и сайты). Форжи пусты -- клоны igareck и поглощённые зеркала;
    # живые ежедневные TG-каналы дали marg 0-2, RU-кластеры раздают ключи
    # только через ботов. Прирост снова дали свои валидаторы и гистовый
    # конвейер: kort0881/vpn-checker-backend -- свой чекер нод, срез RU_Best,
    # автокоммиты 2 раза в день (BLACK +2370, WHITE +330, union +3039 на
    # четвёрку); rekt0ro/ProxyRift -- hourly Actions, +224; гист
    # Darlene-Alderson-FSOCIETY -- сборник брендовых VPN-каналов Telegram,
    # Actions каждые ~10 мин (+115 головной файл, остальные 17 файлов того
    # же конвейера дают ещё ~100 -- при необходимости добираются оттуда).
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend"
    "/main/checked/RU_Best/ru_white_all_BLACK.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend"
    "/main/checked/RU_Best/ru_white_all_WHITE.txt",
    "https://raw.githubusercontent.com/rekt0ro/ProxyRift"
    "/main/subscriptions/all.txt",
    "https://gist.githubusercontent.com/Darlene-Alderson-FSOCIETY"
    "/86fa5f2ad8ff17c182f4009c87c0911b/raw/HiroVPN_Telegram_RE_s_B.txt",
]
# Ревизия 14.09: половина классики отдаёт 404. Экосистема переезжает --
# источники стоит переверять раз в пару месяцев.
# Гибрид: сначала свежий выход коллектора (TG-слой идёт первым по файлу,
# значит и в проверку попадает первым), затем старые объёмные пулы
# как хвост -- дедуп по host:port:uid в fetch_all() схлопнет повторы.
SOURCES = (["out/vless_primary.txt"]
           + [BASE % i for i in range(1, 27) if i != 2]
           + [BASE_GITLAB]
           + EXTRA)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
TRACE_HOST, TRACE_PATH = "www.cloudflare.com", "/cdn-cgi/trace"
DOWN_HOST = "speed.cloudflare.com"
DOWN_BYTES = 262144
DOWN_PATH = "/__down?bytes=%d" % DOWN_BYTES
# Транспорты, которые понимает mihomo. xhttp/httpupgrade он не запустит,
# так что проверять их -- зря жечь время раннера.
NETS = ("tcp", "raw", "ws", "grpc", "h2", "http")


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, flush=True)


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")


# vless:// в дикой природе живёт не только построчно: JSON-массивы
# (DarkRoyalty servers.json), HTML-страницы, склейки без переводов строк.
# Регэксп выдирает URI из любого текста; жадность ограничена классом
# "не пробел и не кавычка", фрагменты с именами (%XX) не ломаются.
VLESS_RE = re.compile(r"vless://[^\s'\"<>\\]+")


def parse_vless(uri):
    if not uri.startswith("vless://"):
        return None
    try:
        u = urllib.parse.urlsplit(uri)
        p = dict(urllib.parse.parse_qsl(u.query))
        host, port, uid = u.hostname, u.port, urllib.parse.unquote(u.username or "")
        if not (host and port and uid):
            return None
        net = p.get("type", "tcp")
        if net not in NETS:
            return None
        sec = p.get("security") or "none"
        sni = p.get("sni") or p.get("host") or host
        fp = p.get("fp") or "chrome"
        st = {"network": net, "security": sec}
        if sec == "reality":
            # Reality без публичного ключа сервера нерабочая по определению:
            # рукопожатие без него не построить, и xray отказывается грузить
            # такой конфиг целиком ("empty password"), унося с собой всю
            # пачку. В списках такого мусора 23%, и это 98% всего брака.
            if not p.get("pbk"):
                return None
            sid = p.get("sid", "")
            if sid:
                try:
                    bytes.fromhex(sid)      # xray падает на нешестнадцатеричном
                except ValueError:
                    return None
            st["realitySettings"] = {"serverName": sni, "fingerprint": fp,
                                     "publicKey": p["pbk"],
                                     "shortId": sid,
                                     "spiderX": p.get("spx", "/")}
        elif sec in ("tls", "xtls"):
            st["security"] = "tls"
            st["tlsSettings"] = {"serverName": sni, "fingerprint": fp,
                                 "allowInsecure": p.get("allowInsecure") in ("1", "true")}
            if p.get("alpn"):
                st["tlsSettings"]["alpn"] = [x for x in p["alpn"].split(",") if x]
        if net == "ws":
            st["wsSettings"] = {"path": p.get("path", "/"),
                                "headers": {"Host": p.get("host") or sni}}
        elif net == "grpc":
            st["grpcSettings"] = {"serviceName": p.get("serviceName", ""),
                                  "multiMode": p.get("mode") == "multi"}
        elif net in ("http", "h2"):
            st["network"] = "http"
            st["httpSettings"] = {"path": p.get("path", "/"),
                                  "host": [p.get("host") or sni]}
        user = {"id": uid, "encryption": p.get("encryption", "none")}
        if p.get("flow"):
            user["flow"] = p["flow"]
        return {"raw": uri, "host": host, "port": port,
                "id": "%s:%s:%s" % (host, port, uid[:8]),
                "outbound": {"protocol": "vless",
                             "settings": {"vnext": [{"address": host, "port": port,
                                                     "users": [user]}]},
                             "streamSettings": st}}
    except Exception:
        return None


def fetch_all():
    def one(url):
        if not url.startswith(("http://", "https://")):
            try:
                with open(url, encoding="utf-8") as f:
                    return f.read()
            except OSError:
                return ""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8", "ignore")
        except Exception as e:
            log("  источник недоступен: %s (%s)"
                % (url.rsplit("/", 1)[-1], type(e).__name__))
            return ""

    out, seen = [], set()
    with ThreadPoolExecutor(max_workers=8) as ex:
        for url, text in zip(SOURCES, ex.map(one, SOURCES)):
            got = 0
            if text and "://" not in text:
                try:
                    text = b64d(text)
                except Exception:
                    text = ""
            for m in VLESS_RE.finditer(text):
                n = parse_vless(m.group(0))
                if n and n["id"] not in seen:
                    seen.add(n["id"])
                    out.append(n)
                    got += 1
            # Раньше пустой ответ и формат без vless были неразличимы --
            # оба молча давали ноль. Источник, который отдаёт 200, но ни
            # одного конфига (сменился формат, уехала ветка), теперь виден
            # в логе сразу, а не на следующем аудите.
            if not got:
                log("  источник пуст или без vless: %s"
                    % url.rsplit("/", 1)[-1])
    return out


# ------------------------------------------------------------------ socks

def recvall(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise ConnectionError("сокет закрыт")
        buf += c
    return buf


def socks_open(port, host, dst_port, timeout):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if recvall(s, 2) != b"\x05\x00":
            raise ConnectionError("socks handshake")
        hb = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb
                  + struct.pack("!H", dst_port))
        rep = recvall(s, 4)
        if rep[1] != 0:
            raise ConnectionError("socks reply %d" % rep[1])
        recvall(s, {1: 6, 4: 18}.get(rep[3]) or (recvall(s, 1)[0] + 2))
        return s
    except Exception:
        s.close()
        raise


_CTX = ssl.create_default_context()


def https_get(port, host, path, timeout, max_bytes=4096, deadline=None):
    raw = socks_open(port, host, 443, timeout)
    try:
        sock = _CTX.wrap_socket(raw, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                      "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
                      % (path, host, UA)).encode())
        buf, end = b"", -1
        while end < 0:
            c = sock.recv(8192)
            if not c:
                break
            buf += c
            end = buf.find(b"\r\n\r\n")
            if len(buf) > 65536:
                break
        head = buf[:end].decode("latin1", "replace") if end >= 0 else ""
        body = buf[end + 4:] if end >= 0 else b""
        got = len(body)
        while got < max_bytes:
            if deadline and time.monotonic() > deadline:
                break
            try:
                c = sock.recv(65536)
            except socket.timeout:
                break
            if not c:
                break
            got += len(c)
            if len(body) < 4096:
                body += c
        return head, body, got
    finally:
        try:
            raw.close()
        except OSError:
            pass


def probe(port, timeout, budget):
    """Рукопожатие, страна выхода, затем прокачка. -> (loc, exit_ip, байт)."""
    head, body, _ = https_get(port, TRACE_HOST, TRACE_PATH, timeout)
    if " 200" not in head.split("\r\n", 1)[0]:
        raise ConnectionError("trace не 200")
    text = body.decode("latin1", "replace")
    loc = re.search(r"^loc=([A-Z]{2})", text, re.M)
    ip = re.search(r"^ip=(\S+)", text, re.M)
    _, _, got = https_get(port, DOWN_HOST, DOWN_PATH, timeout,
                          max_bytes=DOWN_BYTES,
                          deadline=time.monotonic() + budget)
    return (loc.group(1) if loc else "??"), (ip.group(1) if ip else None), got


# ------------------------------------------------------------------ xray

def write_cfg(nodes, base_port):
    cfg = {"log": {"loglevel": "none"}, "inbounds": [], "outbounds": [],
           "routing": {"rules": []}}
    for i, n in enumerate(nodes):
        ob = json.loads(json.dumps(n["outbound"]))
        ob["tag"] = "out%d" % i
        cfg["inbounds"].append({"tag": "in%d" % i, "listen": "127.0.0.1",
                                "port": base_port + i, "protocol": "socks",
                                "settings": {"auth": "noauth", "udp": False}})
        cfg["outbounds"].append(ob)
        cfg["routing"]["rules"].append({"type": "field",
                                        "inboundTag": ["in%d" % i],
                                        "outboundTag": "out%d" % i})
    fd, path = tempfile.mkstemp(suffix=".json", prefix="chk-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    return path


STAT = {"rejected": 0, "fallbacks": 0, "xray_starts": 0, "probe_ok": 0, "probe_fail": 0,
        "probe_secs": 0.0, "slowest": 0.0, "not_ready": 0}

# xray называет виноватый аутбаунд в тексте ошибки: "... with tag out12 ...".
# Регулярка должна совпадать с полным именем тега: вариант "tag o12" не
# встречается ни в одной версии, а несовпадение уводило КАЖДУЮ пачку с битым
# конфигом в медленный поштучный путь (замер 29.10: 116 из 118 пачек, 9 с
# на пачку вместо ~1.5 с).
TAG_RE = re.compile(r"tag\s+out(\d+)")


def sanitize(nodes, xray, base_port):
    """Убирает из пачки конфиги, которые xray откажется грузить.

    Раньше это выяснялось падением процесса, после чего пачка делилась
    пополам -- с реальным запуском xray на каждом уровне рекурсии. Замер:
    82 деления на пачку из 300, 419 с против 11 с у чистой пачки.

    `run -test` разбирает конфиг за ~30 мс, без сети и без запуска сервера,
    и в тексте ошибки называет тег виноватого аутбаунда. Так что искать
    перебором нечего: отбрасываем названного и проверяем снова.
    """
    good = list(nodes)
    for _ in range(len(nodes)):
        cfg = write_cfg(good, base_port)
        try:
            r = subprocess.run([xray, "run", "-test", "-c", cfg],
                               capture_output=True, text=True, timeout=60)
        finally:
            os.unlink(cfg)
        if r.returncode == 0:
            return good
        m = TAG_RE.search(r.stdout + r.stderr)
        if not m or int(m.group(1)) >= len(good):
            # Ошибка не про конкретный аутбаунд. Выбрасывать всю пачку тут
            # нельзя -- так тихо теряются сотни живых нод; проверяем поштучно.
            STAT["fallbacks"] += 1
            log("  -test без тега, перехожу на поштучную: %s"
                % (r.stdout + r.stderr).strip()[-140:])
            return sanitize_each(good, xray, base_port)
        STAT["rejected"] += 1
        good.pop(int(m.group(1)))
        if not good:
            break
    return good


def sanitize_each(nodes, xray, base_port):
    """Запасной путь: каждый конфиг проверяется отдельным -test (~15 мс)."""
    def ok(n):
        cfg = write_cfg([n], base_port)
        try:
            return subprocess.run([xray, "run", "-test", "-c", cfg],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,
                                  timeout=30).returncode == 0
        except Exception:
            return False
        finally:
            try:
                os.unlink(cfg)
            except OSError:
                pass

    with ThreadPoolExecutor(max_workers=16) as ex:
        good = [n for n, v in zip(nodes, ex.map(ok, nodes)) if v]
    STAT["rejected"] += len(nodes) - len(good)
    return good


def wait_ready(port, deadline=15.0):
    """Ждёт, пока xray поднимет инбаунды. Фиксированный sleep тут врал в обе
    стороны: на пачке в 300 инбаундов xray мог не успеть, и живые ноды
    отсеивались как мёртвые, а на маленькой -- зря простаивал."""
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def check_chunk(nodes, xray, base_port, a):
    """Одна пачка нод под одним процессом xray. -> список выживших."""
    nodes = sanitize(nodes, xray, base_port)
    if not nodes:
        return []
    cfg = write_cfg(nodes, base_port)
    proc = subprocess.Popen([xray, "run", "-c", cfg],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    STAT["xray_starts"] += 1
    if not wait_ready(base_port):
        STAT["not_ready"] += 1
        proc.terminate()
        os.unlink(cfg)
        return []
    good = []
    try:
        def one(pair):
            i, n = pair
            t0 = time.monotonic()
            try:
                loc, ip, got = probe(base_port + i, a.timeout, a.budget)
            except Exception:
                STAT["probe_fail"] += 1
                return None
            finally:
                dt = time.monotonic() - t0
                STAT["probe_secs"] += dt
                STAT["slowest"] = max(STAT["slowest"], dt)
            if got < a.min_bytes:
                STAT["probe_fail"] += 1
                return None
            if a.geo_set and loc not in a.geo_set:
                STAT["probe_fail"] += 1
                return None
            STAT["probe_ok"] += 1
            n["loc"], n["exit"], n["bytes"] = loc, ip, got
            return n

        with ThreadPoolExecutor(max_workers=len(nodes)) as ex:
            for r in ex.map(one, list(enumerate(nodes))):
                if r:
                    good.append(r)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        try:
            os.unlink(cfg)
        except OSError:
            pass
    return good


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--shards", type=int, default=1)
    ap.add_argument("--out", default="alive.txt")
    ap.add_argument("--xray", default="./xray")
    ap.add_argument("--tcp-workers", type=int, default=400)
    ap.add_argument("--tcp-timeout", type=float, default=3.0)
    ap.add_argument("--batch", type=int, default=40)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--budget", type=float, default=10.0)
    ap.add_argument("--min-bytes", type=int, default=200000)
    ap.add_argument("--base-port", type=int, default=31000)
    ap.add_argument("--deadline-min", type=int, default=280)
    ap.add_argument("--geo", default="",
                    help="держать только ноды со страной выхода из списка "
                         "US,CA (пусто = все страны)")
    ap.add_argument("--limit", type=int, default=0,
                    help="проверить не больше N нод (для замеров)")
    ap.add_argument("--max-per-host", type=int, default=0,
                    help="брать не больше N конфигов на один host:port "
                         "(0 = без лимита). Один сервер часто приходит "
                         "под многими uid: замер 29.10 -- 44k лишних "
                         "конфигов (26%% пула), максимум 378 на адрес.")
    a = ap.parse_args()
    # Страна выхода известна только после зонда, до него CDN-фронтовые ноды
    # гео не отличить -- фильтр применяется в one(), а не на входе.
    a.geo_set = {x.strip().upper() for x in a.geo.split(",") if x.strip()}

    t_end = time.monotonic() + a.deadline_min * 60
    log("тяну источники...")
    nodes = fetch_all()
    log("уникальных конфигов с пригодным транспортом: %d" % len(nodes))
    if a.max_per_host:
        byhost, trimmed = {}, []
        for n in nodes:
            k = (n["host"], n["port"])
            if byhost.get(k, 0) >= a.max_per_host:
                continue
            byhost[k] = byhost.get(k, 0) + 1
            trimmed.append(n)
        log("лимит %d конфигов на host:port: %d -> %d"
            % (a.max_per_host, len(nodes), len(trimmed)))
        nodes = trimmed
    mine = [n for i, n in enumerate(nodes) if i % a.shards == a.shard]
    log("шард %d/%d -> %d конфигов" % (a.shard, a.shards, len(mine)))
    log("ступень 1: TCP...")
    t0 = time.monotonic()

    def op(n):
        try:
            with socket.create_connection((n["host"], n["port"]),
                                          timeout=a.tcp_timeout):
                return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=a.tcp_workers) as ex:
        reach = [n for n, ok in zip(mine, ex.map(op, mine)) if ok]
    log("  порт открыт у %d из %d (%.0f%%), %.0f с"
        % (len(reach), len(mine), 100.0 * len(reach) / max(len(mine), 1),
           time.monotonic() - t0))

    if a.limit:
        reach = reach[:a.limit]
        log("  ограничение --limit: беру %d" % len(reach))

    log("ступень 2+3: рукопожатие, trace и прокачка %d КБ..."
        % (DOWN_BYTES // 1024))
    alive, done, t_probe, complete = [], 0, time.monotonic(), True
    for i in range(0, len(reach), a.batch):
        if time.monotonic() > t_end:
            log("  бюджет времени исчерпан, остановился на %d из %d"
                % (done, len(reach)))
            complete = False
            break
        chunk = reach[i:i + a.batch]
        tb, rb = time.monotonic(), STAT["rejected"]
        alive += check_chunk(chunk, a.xray, a.base_port, a)
        done += len(chunk)
        log("  пачка %3d: %3d нод за %5.1f с, отбраковано %d, живых всего %d"
            % (i // a.batch + 1, len(chunk), time.monotonic() - tb,
               STAT["rejected"] - rb, len(alive)))
    wall = time.monotonic() - t_probe
    probes = STAT["probe_ok"] + STAT["probe_fail"]
    log("ЗАМЕР: стена %.0f с | стартов xray %d | отбраковано конфигов %d "
        "| пачек не поднялось %d | поштучных проверок %d | зондов %d"
        % (wall, STAT["xray_starts"], STAT["rejected"], STAT["not_ready"],
           STAT["fallbacks"], probes))
    log("ЗАМЕР: суммарно в зондах %.0f с, средний %.1f с, самый долгий %.1f с"
        % (STAT["probe_secs"], STAT["probe_secs"] / max(probes, 1), STAT["slowest"]))
    log("ЗАМЕР: эффективная параллельность %.0fx (сумма зондов / стена)"
        % (STAT["probe_secs"] / max(wall, 1)))

    seen, uniq = set(), []
    for n in alive:                    # один сервер приходит под многими
        k = n.get("exit") or n["id"]   # входами -- в списке нужен один раз
        if k not in seen:
            seen.add(k)
            uniq.append(n)
    # Служебная строка едет вместе со списком: потребителю надо знать не
    # только сколько нод пришло, но и весь ли список успели пройти.
    # parse_vless() на ней возвращает None, так что демону она не мешает.
    stats = ("# STATS shard=%d/%d source=%d mine=%d open=%d checked=%d "
             "alive=%d uniq=%d complete=%d secs=%d geo=%s"
             % (a.shard, a.shards, len(nodes), len(mine), len(reach), done,
                len(alive), len(uniq), 1 if complete else 0, wall,
                ",".join(sorted(a.geo_set)) or "all"))
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(stats + "\n")
        for n in uniq:
            f.write(n["raw"] + "\n")
    log(stats)
    log("ИТОГО: живых %d, после схлопывания по выходному IP %d -> %s"
        % (len(alive), len(uniq), a.out))


if __name__ == "__main__":
    main()
