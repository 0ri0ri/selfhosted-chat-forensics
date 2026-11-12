MODES = {
    "client": {
        "id": "client",
        "name": "Client",
        "title": "클라이언트 분석",
        "description": "사용자 PC 디스크 이미지에서 추출한 데스크톱 앱(Electron) 데이터를 분석합니다.",
    },
    "server": {
        "id": "server",
        "name": "Server",
        "title": "서버 분석",
        "description": "서버 디스크 이미지에서 추출한 애플리케이션, DB 데이터 디렉터리를 분석합니다.",
    },
}

APPS = {
    "mattermost": {"id": "mattermost", "name": "Mattermost", "color": "#1e325c"},
    "zulip": {"id": "zulip", "name": "Zulip", "color": "#6492fe"},
    "rocketchat": {"id": "rocketchat", "name": "Rocket.Chat", "color": "#f5455c"},
}

_OPEN_IMAGE = "디스크 이미지를 읽기 전용으로 마운트하거나 FTK Imager 등 분석 도구로 엽니다."

GUIDES = {
    "client": {
        "mattermost": {
            "summary": "Mattermost Desktop 앱의 사용자 데이터 폴더 전체를 수집합니다.",
            "paths": [
                {"os": "Windows", "path": r"C:\Users\<사용자>\AppData\Roaming\Mattermost"},
            ],
            "steps": [
                _OPEN_IMAGE,
                "위 경로의 폴더를 통째로 내보냅니다(Export).",
                "복사한 폴더를 ZIP 구성 예시를 참고하여 알맞게 압축합니다.",
            ],
            "zip_example": "Mattermost.zip\n`- Mattermost/\n   |- config.json\n   |- Local Storage/leveldb/\n   |- IndexedDB/\n   |- Cache/\n   `- logs/",
            "notes": [
                "PC에 사용자 계정이 여러 개면 계정마다 경로를 확인하고, 앱 데이터가 있는 계정을 수집하세요.",
            ],
        },
        "zulip": {
            "summary": "Zulip Desktop 앱의 사용자 데이터 폴더 전체를 수집합니다.",
            "paths": [
                {"os": "Windows", "path": r"C:\Users\<사용자>\AppData\Roaming\Zulip"},
            ],
            "steps": [
                _OPEN_IMAGE,
                "위 경로의 폴더를 통째로 내보냅니다(Export).",
                "복사한 폴더를 ZIP 구성 예시를 참고하여 알맞게 압축합니다.",
            ],
            "zip_example": (
                "Zulip.zip\n"
                "`- Zulip/\n"
                "   |- config/            (domain.json, settings.json)\n"
                "   |- sentry/            (scope_v3.json)\n"
                "   `- Partitions/\n"
                "      `- webviewsession/\n"
                "         |- Network/Cookies\n"
                "         |- Local Storage/leveldb/\n"
                "         `- Cache/Cache_Data/"
            ),
            "notes": [
                "서버 화면의 쿠키, Local Storage, 캐시는 루트가 아니라 Partitions/webviewsession 아래에 저장됩니다. 접속한 조직이 여러 개여도 이 파티션 하나를 함께 씁니다.",
                "설치 폴더(C:\\Users\\<사용자>\\AppData\\Local\\Programs\\Zulip)는 수집하지 않아도 됩니다. 앱, 서버 버전은 config/domain.json 과 sentry/scope_v3.json 에도 남습니다.",
            ],
        },
        "rocketchat": {
            "summary": "Rocket.Chat Desktop 앱의 사용자 데이터 폴더 전체를 수집합니다.",
            "paths": [
                {"os": "Windows", "path": r"C:\Users\<사용자>\AppData\Roaming\Rocket.Chat"},
            ],
            "steps": [
                _OPEN_IMAGE,
                "위 경로의 폴더를 통째로 내보냅니다(Export). 서버별 데이터는 Partitions\\https%3A\\<서버 호스트> 아래에 있으므로 Partitions 를 빠뜨리지 않습니다.",
                "config.json 이 없으면(삭제됨) 분석 도구로 삭제된 MFT 레코드, $LogFile 에서 이전 판을 찾아 config.json 이름으로 같은 위치에 넣습니다.",
                "복사한 폴더를 ZIP 구성 예시를 참고하여 알맞게 압축합니다.",
            ],
            "zip_example": (
                "Rocket.Chat.zip\n"
                "`- Rocket.Chat/\n"
                "   |- config.json          (등록 서버, 신뢰한 인증서, 창 상태)\n"
                "   |- logs/                (main.log, errors.jsonl)\n"
                "   |- Local State, Preferences, Network/\n"
                "   `- Partitions/\n"
                "      `- https%3A/\n"
                "         `- <서버 호스트>/   (예: 192.168.6.133)\n"
                "            |- IndexedDB/https_<호스트>_0.indexeddb.leveldb/\n"
                "            |- Local Storage/leveldb/\n"
                "            `- Cache/Cache_Data/"
            ),
            "notes": [
                "서버마다 Partitions\\https%3A\\<호스트> 폴더가 따로 생깁니다. 서버를 여러 개 등록했다면 모두 포함하세요.",
                "LevelDB 폴더는 *.log, *.ldb, MANIFEST, CURRENT 를 모두 넣어야 이전 판(삭제, 변경 전 값)까지 복원됩니다.",
                "Local Storage 에 E2E 개인키가 평문으로 남습니다. E2E 방 메시지를 푸는 키이므로 취급에 주의하세요.",
                "설치 폴더(C:\\Users\\<사용자>\\AppData\\Local\\Programs\\Rocket.Chat)는 수집하지 않아도 됩니다.",
            ],
        },
    },
    "server": {
        "mattermost": {
            "summary": "Mattermost 설정, 데이터, 로그 디렉터리와 PostgreSQL 데이터 디렉터리를 수집합니다.",
            "paths": [
                {"os": "설정", "path": "/opt/mattermost/config/*"},
                {"os": "데이터", "path": "/opt/mattermost/data/*"},
                {"os": "로그", "path": "/opt/mattermost/logs/*"},
                {"os": "PostgreSQL", "path": "/var/lib/postgresql/*"},
            ],
            "steps": [
                _OPEN_IMAGE,
                "/opt/mattermost 아래 config, data, logs 디렉터리만 내보냅니다 (나머지 바이너리, 플러그인은 제외).",
                "/var/lib/postgresql 디렉터리 전체를 내보냅니다.",
                "수집한 디렉터리를 하나의 폴더에 모아 ZIP 구성 예시를 참고하여 압축합니다.",
            ],
            "zip_example": (
                "mattermost_server.zip\n"
                "|- opt/mattermost/\n"
                "|  |- config/\n"
                "|  |- data/\n"
                "|  `- logs/\n"
                "`- var/lib/postgresql/\n"
                "   `- <버전>/main/   (PostgreSQL 데이터 디렉터리)"
            ),
            "notes": [
                "PostgreSQL 데이터 디렉터리가 기본 위치에 없으면 /etc/postgresql/<버전>/main/postgresql.conf 의 data_directory 값을 확인하세요.",
                "Docker로 배포한 경우 /var/lib/docker/volumes/ 아래 Mattermost, DB 볼륨을 수집하세요.",
            ],
        },
        "zulip": {
            "summary": "Zulip 설정, 로그, 업로드 디렉터리와 PostgreSQL 데이터 디렉터리를 수집합니다.",
            "paths": [
                {"os": "설정", "path": "/etc/zulip/*"},
                {"os": "로그", "path": "/var/log/zulip/*"},
                {"os": "업로드", "path": "/home/zulip/uploads/*"},
                {"os": "PostgreSQL", "path": "/var/lib/postgresql/*"},
                {"os": "버전 (선택)", "path": "/home/zulip/deployments/<타임스탬프>/version.py"},
            ],
            "steps": [
                _OPEN_IMAGE,
                "/etc/zulip, /var/log/zulip, /home/zulip/uploads 디렉터리를 내보냅니다.",
                "/var/lib/postgresql 디렉터리 전체를 내보냅니다.",
                "(선택) /home/zulip/deployments 아래 타임스탬프 폴더(예: 2026-10-25-16-45-27)에서 version.py 만 내보냅니다.",
                "수집한 디렉터리를 하나의 폴더에 모아 ZIP 구성 예시를 참고하여 압축합니다.",
            ],
            "zip_example": (
                "zulip_server.zip\n"
                "|- etc/zulip/            (settings.py, zulip.conf, zulip-secrets.conf)\n"
                "|- var/log/zulip/        (server.log, django.log, install.log …)\n"
                "|- home/zulip/\n"
                "|  |- uploads/           (files/, avatars/)\n"
                "|  `- deployments/<타임스탬프>/version.py   (선택)\n"
                "`- var/lib/postgresql/\n"
                "   `- <버전>/main/       (PostgreSQL 데이터 디렉터리)"
            ),
            "notes": [
                "deployments/current 는 심볼릭 링크라 디스크 이미지에서 따라가지지 않을 수 있습니다. 실제 타임스탬프 폴더에서 version.py 를 꺼내세요. 코드 전체는 크기가 커서 수집하지 않아도 됩니다 (버전은 install.log 에도 남습니다).",
                "로그는 회전된 파일(server.log.1, *.gz 등)까지 폴더째 수집하세요.",
                "/etc/zulip/zulip-secrets.conf 에는 비밀번호, 키가 들어 있으므로 취급에 주의하세요.",
                "업로드 경로는 /etc/zulip/settings.py 의 LOCAL_UPLOADS_DIR 값으로 확인합니다 (S3 저장소 사용 시 디스크에 없음).",
            ],
        },
        "rocketchat": {
            "summary": "Docker 로 운영한 Rocket.Chat 의 MongoDB 데이터 디렉터리, 컨테이너 정보, 로그, compose 설정을 수집합니다.",
            "paths": [
                {"os": "MongoDB", "path": "/var/lib/docker/volumes/<프로젝트>_mongodb_data/_data/*"},
                {"os": "컨테이너", "path": "/var/lib/docker/containers/*"},
                {"os": "compose", "path": "/home/<사용자>/rocketchat-compose/ (.env, compose*.yml)"},
                {"os": "셸 기록", "path": "/home/<사용자>/.bash_history, /root/.bash_history"},
            ],
            "steps": [
                _OPEN_IMAGE,
                "/var/lib/docker/volumes 에서 MongoDB 볼륨(예: rocketchat-compose_mongodb_data)의 _data 폴더를 통째로 내보냅니다 (WiredTiger*, _mdb_catalog.wt, sizeStorer.wt, collection-*.wt, index-*.wt, journal/ 전부).",
                "/var/lib/docker/containers 아래 컨테이너 폴더를 내보냅니다 (config.v2.json, hostconfig.json, <ID>-json.log).",
                "rocketchat-compose 폴더의 .env, compose*.yml 과 사용자 홈의 .bash_history 를 내보냅니다.",
                "수집한 항목을 원래 경로 구조 그대로 하나의 폴더에 모아 ZIP 구성 예시를 참고하여 압축합니다.",
            ],
            "zip_example": (
                "rocketchat_server.zip\n"
                "|- var/lib/docker/\n"
                "|  |- volumes/rocketchat-compose_mongodb_data/_data/\n"
                "|  |    (WiredTiger.turtle, WiredTiger.wt, _mdb_catalog.wt,\n"
                "|  |     collection-*.wt, index-*.wt, journal/ …)\n"
                "|  `- containers/<컨테이너 ID>/\n"
                "|       (config.v2.json, <ID>-json.log)\n"
                "`- home/<사용자>/\n"
                "   |- rocketchat-compose/   (.env, compose.yml, compose.database.yml …)\n"
                "   `- .bash_history"
            ),
            "notes": [
                "MongoDB 는 덤프가 아니라 데이터 디렉터리를 그대로 해석합니다 (mongod 를 띄우지 않음). 레플리카셋(rs0)이면 local.oplog.rs 로 지운 메시지, 첨부의 원래 내용과 삭제 시각을 복원합니다.",
                "볼륨 이름은 compose 프로젝트 이름에 따라 다릅니다. /var/lib/docker/volumes 에서 WiredTiger.turtle 이 들어 있는 _data 폴더를 찾으세요.",
                "Docker 없이 설치했다면 MongoDB 는 /var/lib/mongodb (mongod.conf 의 storage.dbPath), Snap 설치는 /var/snap/rocketchat-server/common/ 아래에 있습니다.",
                "첨부가 기본값(GridFS)이면 MongoDB 안에 있습니다. FileUpload_Storage_Type 이 FileSystem 이면 FileUpload_FileSystemPath 디렉터리도 수집하세요.",
                "E2E 방의 메시지, 첨부는 서버에 암호문만 있습니다. 복호화 키는 클라이언트(Rocket.Chat Desktop) 증거에 있습니다.",
                "mongod 로그(컨테이너 json.log)는 수십 MB 가 될 수 있습니다. 화면에는 경고, 오류와 시작, 저장소, 복제 관련 줄만 보입니다.",
            ],
        },
    },
}


def is_valid(mode: str, app: str) -> bool:
    return mode in MODES and app in APPS


def get_mode_apps(mode: str) -> list[dict]:
    return [{**APPS[app_id], "guide": GUIDES[mode][app_id]} for app_id in APPS]
