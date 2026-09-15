#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сбор vless-конфигов с первоисточников -- Telegram-каналов напрямую.

Агрегаторы (AvenCores, Epodonios, mheidari98 и пр.) перепродают один и тот
же телеграм-поток с задержкой на свой cron: канал -> скрейпер (до часа) ->
агрегатор (ещё до часа) -> агрегатор агрегатора. Нода, живущая считанные
часы, доходит до проверки уже мёртвой. Здесь убраны все посредники:
читается публичное превью https://t.me/s/<канал> -- без аккаунта, без API --
и несколько прямых списков, которые не телеграм и не перепродажа.

Чем схема отличается от чужих парсеров:
  * окно свежести по <time> сообщения (агрегаторы забирают всё подряд,
    включая многодневный мусор);
  * <wbr>-разрывы длинных ссылок склеиваются, HTML-сущности раскрываются;
  * лёгкая валидация до записи (reality без pbk, битые порты/хосты) --
    тот же фильтр, что в checker.py, срезает мусор до проверки;
  * мёртвые каналы пишутся отдельным файлом, а не молча выпадают.

Если t.me недоступен с текущего адреса (РКН), прокидывается любой http(s)-
прокси: --proxy http://127.0.0.1:8080 или переменная HTTPS_PROXY.
"""
import argparse
import base64
import html
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
CHANNELS_FILE = "channels_merged.txt"

# Ссылки в постах -- печатный ASCII: обрез по \\x21-\\x7E останавливает матч
# на персидском тексте и эмодзи, которые иначе приклеиваются к хвосту ссылки.
URI_RE = re.compile(r"(?:vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|juicity)"
                    r"://[\x21-\x7E]+")
# Тот же фильтр транспорта, что в checker.py: mihomo всё равно не поднимет
# остальные, проверять их -- зря жечь слоты.
NETS = ("tcp", "raw", "ws", "grpc", "h2", "http")

# Прямые нетелеграм-списки. Оставлено только то, что либо само проверяет
# ноды, либо единственно в своём роде (RF-отбор); перепродавцы выкинуты.
STATIC = [
    # РФ-специфичные: отобраны/проверены на работу из России.
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia"
    "/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia"
    "/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://s3c3.001.gpucloud.ru/wlr/wl.txt",
    "https://etoneya.su/whitelist",
    "https://etoneya.su/1",
    # GitVerse доступен из РФ напрямую, без прокси.
    "https://gitverse.ru/api/repos/ru-wbl/wl/raw/branch/master/"
    "KvRuVPN%2FKvRuVPN.txt",
    "https://gitverse.ru/api/repos/MishaLan/MishaLan/raw/branch/master/"
    "MishaLan.txt",
    "https://gitverse.ru/api/repos/flaafix/AetrisVPN_Black_list/raw/"
    "branch/master/configs.txt",
    # Самопроверяющиеся: гоняют трафик сами, брака почти нет.
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output/"
    "all_valid_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified.txt",
    # Живой TG-поток чужими руками: свои боты/аккаунты читают каналы
    # в реальном времени -- это те же первоисточники, только с доставкой.
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/"
    "splitted/vless",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list"
    "/main/vless_configs.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI"
    "/tg-v2ray-configs-every2h/main/Original-Configs.txt",
    # Вторичные: небольшой объём, но лишними не бывают.
    "https://robin.victoriacross.ir",
    "https://sub.irys.dpdns.org/auto",
    "https://rahi-eq3.pages.dev/api/configs?limit=all",
    "https://trojanvmess.pages.dev/cmcm?b64",
]


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, flush=True)


_opener = None


def http_get(url, timeout, wall=None):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept-Language": "en;q=0.9,ru;q=0.8",
        # messagesDesktopMode=0 отдаёт текст сообщений одним куском --
        # так же делает MhdiTaheri; без него часть постов приходит пустой.
        "Cookie": "messagesDesktopMode=0",
    })
    with _opener.open(req, timeout=timeout) as r:
        if wall is None:
            return r.read().decode("utf-8", "ignore")
        # wall -- бюджет по часам на всё тело: drip-серверы (etoneya.su
        # отдаёт ~250 байт/с и подвисает) иначе не читаются никаким
        # сокет-таймаутом. Что успело прийти -- то и берём: целые ссылки
        # регулярка вытащит, обрезанный хвост отбракуется в vless_key.
        end, buf = time.monotonic() + wall, []
        while time.monotonic() < end:
            try:
                c = r.read1(65536)
            except Exception:
                break
            if not c:
                break
            buf.append(c)
        return b"".join(buf).decode("utf-8", "ignore")


def get(url, timeout, retries=2, wall=None):
    for i in range(retries + 1):
        try:
            return http_get(url, timeout, wall=wall)
        except Exception:
            if i == retries:
                raise
            time.sleep(1.5 * (i + 1))


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")


def http_get_final(url, timeout):
    """-> (тело, конечный URL после редиректов). t.me/s/<канал> при
    выключенном админом превью молча редиректит на карточку t.me/<канал> --
    без проверки конечного URL это выглядит как «канал без сообщений»."""
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept-Language": "en;q=0.9,ru;q=0.8",
        "Cookie": "messagesDesktopMode=0",
    })
    with _opener.open(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore"), r.geturl()


# ------------------------------------------------------------------ telegram

def parse_page(page):
    """[(время сообщения | None, [ссылки...])] -- по блокам сообщений."""
    out = []
    for chunk in page.split("tgme_widget_message_wrap")[1:]:
        t = re.search(r'datetime="(\d{4}-\d{2}-\d{2}T[\d:]+\+00:00)"', chunk)
        # <wbr> рвёт длинные ссылки -- вырезать теги до извлечения;
        # href-вариант ловит ссылки, запакованные в <a href="...">.
        text = re.sub(r"<[^>]+>", "", chunk)
        text = html.unescape(text)
        hrefs = html.unescape(urllib.parse.unquote(
            " ".join(re.findall(r'href="([^"]+)"', chunk))))
        links = set(URI_RE.findall(text)) | set(URI_RE.findall(hrefs))
        if links:
            out.append((t.group(1) if t else None, links))
    return out


def harvest_channel(ch, pages, hours, timeout):
    """-> (ссылки, причина_смерти | None)"""
    url = "https://t.me/s/%s" % ch
    try:
        page, final = http_get_final(url, timeout)
    except Exception:
        return None, "недоступен"
    if "tgme_widget_message" not in page:
        # редирект на карточку = превью выключено админом, вебом не читается
        # в принципе (только MTProto-аккаунтом); заглушка без редиректа --
        # канал удалён либо пуст.
        if final.rstrip("/") != url.rstrip("/"):
            return None, "превью выключено"
        return None, ("удалён/пустой"
                      if "tgme_page_title" in page else "нет сообщений")
    kept, cutoff = [], time.time() - hours * 3600
    for _ in range(pages):
        for when, links in parse_page(page):
            if when:
                try:
                    ts = datetime.fromisoformat(when).timestamp()
                except ValueError:
                    ts = None
                if ts is not None and ts < cutoff:
                    continue
            kept += links
        ids = [int(x) for x in re.findall(r'data-post="%s/(\d+)"'
                                          % re.escape(ch), page)]
        if not ids or len(ids) < 20:     # короткая страница -- история кончилась
            break
        try:
            page = get("%s?before=%d" % (url, max(ids)), timeout)
        except Exception:
            break
    return kept, None


# ------------------------------------------------------------------ фильтры

def vless_key(uri):
    """Ключ дедупа или None для мусора. Совпадает по смыслу с checker.py:
    transport из NETS, reality строго с pbk и hex-sid, валидные host:port."""
    try:
        u = urllib.parse.urlsplit(uri)
        p = dict(urllib.parse.parse_qsl(u.query))
        host, port, uid = u.hostname, u.port, urllib.parse.unquote(u.username or "")
        if not (host and port and uid):
            return None
        if p.get("type", "tcp") not in NETS:
            return None
        if host.lower() in ("localhost", "0.0.0.0") or host.startswith("127.") \
                or host.endswith(".onion"):
            return None
        sec = p.get("security") or "none"
        if sec == "reality":
            if not p.get("pbk"):
                return None
            sid = p.get("sid", "")
            if sid:
                try:
                    bytes.fromhex(sid)
                except ValueError:
                    return None
        return "%s:%s:%s" % (host.lower(), port, uid.lower())
    except Exception:
        return None


def trim(link):
    # Концевую пунктуацию и кавычки срезаем: ссылка в тексте поста часто
    # запятой или скобкой продолжается, а href-хвост несёт закрывающую кавычку.
    return link.rstrip("),.;!?'\"")


def collect_vless(chunks, seen, out):
    """Каждая ссылка -> (ключ, сырая строка); мусор и дубли отсеиваются."""
    raw = 0
    for links in chunks:
        for link in links:
            link = trim(link)
            raw += 1
            k = vless_key(link) if link.startswith("vless://") else None
            if k and k not in seen:
                seen.add(k)
                out.append(link)
    return raw


# ------------------------------------------------------------------ статика

def fetch_static(timeout):
    # etoneya.su отдаёт тело по капле и в 20 с не укладывается -- для статики
    # таймаут ниже 45 с сам себе режет источники.
    timeout = max(timeout, 45.0)

    def one(url):
        # etoneya.su: 120 с по часам вместо сокет-таймаутов -- сервер
        # отдаёт тело каплями и вешает соединение; за это время приходит
        # почти весь файл (~20 из ~25 КБ).
        try:
            if "etoneya.su" in url:
                text = http_get(url, 20.0, wall=120.0)
            else:
                text = get(url, timeout, retries=1)
        except Exception as e:
            log("  источник недоступен: %s (%s)"
                % (url.rsplit("/", 1)[-1][:40] or url, type(e).__name__))
            return []
        if "://" not in text:
            try:
                text = b64d(text)
            except Exception:
                return []
        return re.findall(r"vless://[\x21-\x7E]+", text)

    seen, out = set(), []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for links in ex.map(one, STATIC):
            for link in links:
                k = vless_key(trim(link))
                if k and k not in seen:
                    seen.add(k)
                    out.append(link)
    return out


# ------------------------------------------------------------------ main

def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--channels", default=CHANNELS_FILE)
    ap.add_argument("--hours", type=float, default=48.0,
                    help="окно свежести постов (0 = без фильтра)")
    ap.add_argument("--pages", type=int, default=2,
                    help="страниц истории на канал (~20 постов на страницу)")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--limit", type=int, default=0,
                    help="взять первые N каналов (для замеров)")
    ap.add_argument("--no-static", action="store_true")
    ap.add_argument("--no-tg", action="store_true")
    ap.add_argument("--no-mtproto", action="store_true",
                    help="не вливать out/vless_mtproto.txt (выход mt_reader.py)")
    ap.add_argument("--no-retry-dead", action="store_true",
                    help="не делать медленный второй проход по мёртвым")
    ap.add_argument("--proxy", default=None,
                    help="http(s)-прокси для доступа к t.me (или env HTTPS_PROXY)")
    ap.add_argument("--out-dir", default="out")
    a = ap.parse_args()

    global _opener
    handlers = [urllib.request.ProxyHandler(
        {"http": a.proxy, "https": a.proxy} if a.proxy else None)]
    _opener = urllib.request.build_opener(*handlers)
    os.makedirs(a.out_dir, exist_ok=True)

    t0, seen, tg_links = time.monotonic(), set(), []
    dead, alive_ch, raw_total = [], 0, 0
    if not a.no_tg:
        names = []
        for line in open(a.channels, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#"):
                names.append(line)
        if a.limit:
            names = names[:a.limit]
        log("каналов в списке: %d (окно свежести %.0f ч, страниц %d)"
            % (len(names), a.hours, a.pages))

        def work(ch):
            links, why = harvest_channel(ch, a.pages, a.hours, a.timeout)
            return ch, links, why

        res = {}
        with ThreadPoolExecutor(max_workers=a.workers) as ex:
            for i, (ch, links, why) in enumerate(ex.map(work, names), 1):
                res[ch] = (links, why)
                if i % 100 == 0:
                    log("  %d/%d каналов" % (i, len(names)))

        # Часть "мёртвых" -- ложные срабатывания: при серии запросов t.me
        # иногда подсовывает карточку вместо истории. Медленный одиночный
        # повтор с паузами вылавливает таких обратно.
        gone = [ch for ch, (l, w) in res.items() if w]
        if gone and not a.no_retry_dead:
            log("второй проход по %d подозрительным (по одному, с паузами)..."
                % len(gone))
            for ch in gone:
                res[ch] = harvest_channel(ch, a.pages, a.hours, a.timeout)
                time.sleep(2)

        for ch, (links, why) in res.items():
            if why:
                dead.append("%s\t%s" % (ch, why))
            else:
                alive_ch += 1
                raw_total += collect_vless([links], seen, tg_links)
        rec = sum(1 for ch in gone if not res[ch][1])
        log("telegram: живых каналов %d, мёртвых %d (второй проход вернул %d), "
            "ссылок-сырья %d, уникальных валидных vless %d за %.0f с"
            % (alive_ch, len(dead), rec, raw_total, len(tg_links),
               time.monotonic() - t0))
        with open(os.path.join(a.out_dir, "dead_channels.txt"), "w",
                  encoding="utf-8") as f:
            f.write("\n".join(dead) + "\n")

    # MTProto-слой: каналы с выключенным веб-превью читает аккаунт
    # (mt_reader.py, ферма TelegramExpert); его выхлоп вливается сразу
    # после веб-слоя -- до статики, чтобы свежее проверялось первым.
    if not a.no_mtproto:
        mt = os.path.join(a.out_dir, "vless_mtproto.txt")
        if os.path.exists(mt):
            n0 = len(tg_links)
            for line in open(mt, encoding="utf-8"):
                link = line.strip()
                k = vless_key(link) if link.startswith("vless://") else None
                if k and k not in seen:
                    seen.add(k)
                    tg_links.append(link)
            log("mtproto-слой: +%d уникальных из %s" % (len(tg_links) - n0, mt))

    st_links = []
    if not a.no_static:
        log("статические первоисточники: %d URL..." % len(STATIC))
        st_seen = set()
        st_links = fetch_static(a.timeout)
        log("статика: уникальных валидных vless %d" % len(st_links))

    # TG-слой -- главный, статика догоняет тем, чего в каналах не было.
    for link in st_links:
        k = vless_key(link)
        if k and k not in seen:
            seen.add(k)
            tg_links.append(link)
    path = os.path.join(a.out_dir, "vless_primary.txt")
    with open(path, "w", encoding="utf-8") as f:
        for link in tg_links:
            f.write(link + "\n")
    log("ИТОГО: %d уникальных vless -> %s за %.0f с"
        % (len(tg_links), path, time.monotonic() - t0))


if __name__ == "__main__":
    main()
