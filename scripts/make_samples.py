import json
import zipfile
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"

SAMPLES = {
    "client_mattermost": {
        "Mattermost/config.json": json.dumps({"version": 3, "teams": [{"name": "Corp", "url": "https://chat.corp.example.com"}]}),
        "Mattermost/Local Storage/leveldb/000003.log": "dummy leveldb log",
        "Mattermost/Local Storage/leveldb/CURRENT": "MANIFEST-000001\n",
        "Mattermost/IndexedDB/https_chat.corp.example.com_0.indexeddb.leveldb/000005.ldb": "dummy",
        "Mattermost/Cache/Cache_Data/f_0001a3": "dummy cache",
        "Mattermost/logs/main.log": "[2026-10-20 09:08:51] app ready\n",
    },
    "client_zulip": {
        "Zulip/config/settings.json": json.dumps({"autoUpdate": True, "trayIcon": True}),
        "Zulip/config/domain.json": json.dumps({"domains": [{"url": "https://lab.zulipchat.com", "alias": "Research Lab"}]}),
        "Zulip/sentry/scope_v3.json": json.dumps({"scope": {"breadcrumbs": []}}),
        "Zulip/Partitions/webviewsession/Network/Cookies": "dummy",
        "Zulip/Partitions/webviewsession/Local Storage/leveldb/000003.log": "dummy",
        "Zulip/Partitions/webviewsession/Cache/Cache_Data/index": "dummy",
    },
    "client_rocketchat": {
        "Rocket.Chat/config.json": json.dumps({"servers": [{"url": "https://rc.ops.example.com/", "title": "Ops", "version": "8.9.0",
                                                           "userLoggedIn": True, "lastPath": "/group/incident"}],
                                               "trustedCertificates": {}, "downloads": {}}),
        "Rocket.Chat/logs/main.log": "[2026-10-19 22:40:00.000] [info]  Starting Rocket.Chat Desktop application\n",
        "Rocket.Chat/Local State": json.dumps({"uninstall_metrics": {"installation_date2": "1792834448"}}),
        "Rocket.Chat/Partitions/https%3A/rc.ops.example.com/Local Storage/leveldb/000003.log": "dummy",
        "Rocket.Chat/Partitions/https%3A/rc.ops.example.com/IndexedDB/https_rc.ops.example.com_0.indexeddb.leveldb/000003.log": "dummy",
    },
    "server_mattermost": {
        "opt/mattermost/config/config.json": json.dumps({"ServiceSettings": {"SiteURL": "https://chat.corp.example.com"}}),
        "opt/mattermost/logs/mattermost.log": '{"timestamp":"2026-10-21 02:55:13","msg":"login"}\n',
        "opt/mattermost/data/users/abc123/profile.png": "dummy",
        "var/lib/postgresql/16/main/PG_VERSION": "16\n",
        "var/lib/postgresql/16/main/base/16384/1259": "dummy relation file",
        "var/lib/postgresql/16/main/pg_wal/000000010000000000000001": "dummy wal",
    },
    "server_zulip": {
        "etc/zulip/zulip.conf": "[machine]\npuppet_classes = zulip::profile::standalone\n",
        "etc/zulip/settings.py": 'EXTERNAL_HOST = "lab.zulip.example.org"\nLOCAL_UPLOADS_DIR = "/home/zulip/uploads"\n',
        "var/log/zulip/server.log": "2026-10-22 08:30:00 INFO login\n",
        "home/zulip/uploads/files/2/ab/report.pdf": "dummy",
        "home/zulip/deployments/2026-10-20-09-00-00/version.py": 'ZULIP_VERSION = "9.2"\n',
        "var/lib/postgresql/16/main/PG_VERSION": "16\n",
        "var/lib/postgresql/16/main/base/16384/1259": "dummy relation file",
    },
    "server_rocketchat": {
        "var/lib/docker/volumes/rocketchat-compose_mongodb_data/_data/WiredTiger": "WiredTiger\n",
        "var/lib/docker/volumes/rocketchat-compose_mongodb_data/_data/collection-0-1234567890.wt": "dummy",
        "var/lib/docker/containers/0123456789ab/config.v2.json": json.dumps({"Name": "/rocketchat-compose-rocketchat-1",
                                                                             "Config": {"Image": "registry.rocket.chat/rocketchat/rocket.chat:8.9.0"}}),
        "home/rocket/rocketchat-compose/.env": "RELEASE=8.9.0\nROOT_URL=https://rc.ops.example.com\n",
        "home/rocket/.bash_history": "docker compose up -d\n",
    },
}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, files in SAMPLES.items():
        path = OUT / f"{name}.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            for arc, content in files.items():
                z.writestr(arc, content)
        print(f"생성: {path}")


if __name__ == "__main__":
    main()
