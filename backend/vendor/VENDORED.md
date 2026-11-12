# 가져온 외부 코드

## postgresql_viewer (PostgreSQL Viewer 엔진)

- 출처: https://github.com/ws1004/postgresql-viewer 의 `pgviewer` 패키지 (이 저장소에서는 폴더 이름만 `postgresql_viewer` 로 바꿈)
- 라이선스: MIT (Copyright (c) 2026 ws1004) - `postgresql_viewer/LICENSE` (출처 저장소의 LICENSE 를 넣음)
- 가져온 날짜: 2026-10-25
- 범위: `source.py`, `engine/postgres/*` (웹 계층 `api/` 와 화면은 제외)
- 수정: 문구의 긴 대시를 짧은 대시(-)로, 가운뎃점 구분자를 쉼표로 바꾼 것뿐 (동작 변경 없음). 아래 해시는 바꾼 뒤의 값이다.
- 의존성: Python 표준 라이브러리만

가져올 때의 파일 SHA-256:

```
059faea8eb22fca3fcb92d8bcf7eedade0c4df1f5471ffd984b95a3d194927ab *postgresql_viewer/__init__.py
8d0e39c6f7e86c0f72ffc99f22842e65eeed8fc8ed171b15ae5b74c2993399f1 *postgresql_viewer/source.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 *postgresql_viewer/engine/__init__.py
202ec4af6220852716923be38d39dea12a832cdd219c2bb88fc679156b3ec59c *postgresql_viewer/engine/postgres/__init__.py
817533733f22afcf102a3d965ec93b970f273c1ff23c4f98a7af849fca94d17a *postgresql_viewer/engine/postgres/btree.py
e45985b7bf4ad841a50303802799604d27c20c0872dbafa63adcc6dca89ac3d2 *postgresql_viewer/engine/postgres/carve.py
a0f522f3f2b5cf4f9b33b2d2acf4eccf207a1d7b19e428f9b979e00fec0ed1e7 *postgresql_viewer/engine/postgres/clog.py
4fcf0d43e9baee3a8b625e4cad5dddb4a6e3d5aae32049e32ac2839186a4f5f4 *postgresql_viewer/engine/postgres/cluster.py
e356f4a6846eefabd991b0a848784b3d78ae14ff724597e056b452038cc2d852 *postgresql_viewer/engine/postgres/control.py
5d08b88fd683eb4be51425ceff60808e8cc0fa778c054c8cad1e20af1185243f *postgresql_viewer/engine/postgres/crc32c.py
4e14b4dafacfabdd484d9002a5e53b8cc209c1091718404980bc6155fb675a99 *postgresql_viewer/engine/postgres/heap.py
444ae0f6ca1a3924d31ee852a971f21d0075c5cb39fbaa0976cfee17c075f606 *postgresql_viewer/engine/postgres/recovery.py
b4c253cdd466e56f1f46a460d775534c0fe685470c8ff455f91614280c361ed1 *postgresql_viewer/engine/postgres/relmap.py
93648d5dc872691959c8106d048560a16373f3b3075881aa4148dc8816bf9d47 *postgresql_viewer/engine/postgres/types.py
74e34f019aa713048062e39a7a17dd3e397e95432e96399f9adaa856b2ad3770 *postgresql_viewer/engine/postgres/varlena.py
461460ba10b5e8975ee8e10c154192a0cdb0c66abef9e6e20965155f1de35ab9 *postgresql_viewer/engine/postgres/wal.py
```

## ccl_chromium_reader (수정판)

- 출처: https://github.com/ws1004/ccl_chromium_reader_edit 의 `ccl_chromium_reader` 패키지
  (CCL Forensics 의 cclgroupltd/ccl_chromium_reader 0.3.14 를 오류 수정한 판. 커밋 ef4dbed 와 .py 전체 동일 확인, 2026-11-12)
- 라이선스: MIT (Copyright 2020, CCL Forensics) - `ccl_chromium_reader/LICENSE`
- 가져온 날짜: 2026-10-25
- 범위: 패키지 전체 (.py). 이 도구에서 쓰는 모듈: storage_formats/ccl_leveldb, ccl_simplesnappy,
  ccl_chromium_localstorage, ccl_chromium_indexeddb, serialization_formats/ccl_v8, blink_value_deserializer,
  ccl_chromium_cache
- 수정: 없음. 패키지 내부의 절대 import 때문에 `backend/vendor/__init__.py` 가 이 폴더를 sys.path 에 올린다.
- 의존성: 위 모듈은 표준 라이브러리만 사용 (brotli 는 profile_folder 와 cache 의 CLI 부분에서만 import)

가져올 때의 파일 SHA-256:

```
5402892d7c179adc0170611681999c4421506b72c46369294b0ded0abd2a6473 *ccl_chromium_reader/__init__.py
087c6897d07c9e7185a655691298f389325b7adcbc6b8358129a2846d0e3f40e *ccl_chromium_reader/ccl_chromium_cache.py
202ef2e0c8edf64c32d9e7a8eafa621a620adda07b3993c068872984b486c381 *ccl_chromium_reader/ccl_chromium_filesystem.py
37d001c66ae217078ea2ca61629ad6dab86da32fdabbecdde599b07a65708df4 *ccl_chromium_reader/ccl_chromium_history.py
c969dd1d051eab34567050535285e71bca45f9387013e6caa1abab5b001f04fe *ccl_chromium_reader/ccl_chromium_indexeddb.py
f6806c5ca7f64185a76e4cbbb48bcab855ecdb504c560906e90a477fa55b6560 *ccl_chromium_reader/ccl_chromium_localstorage.py
1ea1c5ed9bb1252651a1e5ca44b56f8b1d2ba6dd69e13994470be826a07e3f5e *ccl_chromium_reader/ccl_chromium_notifications.py
4e535c2fabe015a53be5ee720ca2aa020a10786835bda2b9fb5189b504ce2afc *ccl_chromium_reader/ccl_chromium_profile_folder.py
2d79ddec3e9972eecf6092192e8f6bf031807c70f60a2a5446ec5946030a13fa *ccl_chromium_reader/ccl_chromium_sessionstorage.py
f1afc6085e92c43eaa2a8ad02f8aa75c7d292a8ff39d91fd55f8b4bbefb4b791 *ccl_chromium_reader/ccl_chromium_snss2.py
d08280990e8e6e315cc4b5edbace31831bb2b72dcc74ca19e6db3c61fe413d5b *ccl_chromium_reader/ccl_shared_proto_db_downloads.py
c6b3d3b440f565b0e9d19cf4986066c2052c6ccad2d1b84c53ae9d6dfef01425 *ccl_chromium_reader/common.py
a909fc157d618d98caccb41d83c6197efdc545ad7803763f9280269247b2ff10 *ccl_chromium_reader/download_common.py
872876521caccd2f03f52b2cbdb360ba96aef5f486b6d5bece52e298c5a2f36a *ccl_chromium_reader/profile_folder_protocols.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 *ccl_chromium_reader/serialization_formats/__init__.py
fc34c567241500f5cf85357e2c2ffb723f8d225a94aba08f1a00769769668706 *ccl_chromium_reader/serialization_formats/ccl_blink_value_deserializer.py
4fce0c7157815e47ba518b649e28c65d68551eee3be2fde977c1c1c1f363b98a *ccl_chromium_reader/serialization_formats/ccl_easy_chromium_pickle.py
ff26bc9a2cacfd4d94ff8677cf970a794b77884b45b77dde379279100a335846 *ccl_chromium_reader/serialization_formats/ccl_protobuff.py
c4753c211c97d797dd40052d0902482bccd5642010d80399bfe48f60becac9a8 *ccl_chromium_reader/serialization_formats/ccl_v8_value_deserializer.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 *ccl_chromium_reader/storage_formats/__init__.py
cf1297c6c73939ff5e34674bc3c046b84479f67bc6ae301152c5f00d82743177 *ccl_chromium_reader/storage_formats/ccl_leveldb.py
7436f4fc0c3fdbc52674c17881ab90a05f57b633bd498f06697e08bd6fc287ae *ccl_chromium_reader/storage_formats/ccl_simplesnappy.py
```

## mongodb_viewer (MongoDB Viewer 엔진)

- 출처: https://github.com/ws1004/mongodb-viewer 의 `mongoviewer` 패키지 (MIT, 이 저장소에서는 폴더 이름만 `mongodb_viewer` 로 바꿈)
- 가져온 날짜: 2026-11-07
- 범위: `__init__.py`, `source.py`, `engine/__init__.py`, `engine/mongo/*` (웹 계층 `api/` 와 화면은 제외), `LICENSE`
- 수정: 문구의 긴 대시를 짧은 대시(-)로, 가운뎃점 구분자를 쉼표로 바꾼 것뿐 (동작 변경 없음). 아래 해시는 바꾼 뒤의 값이다.
- 의존성: Python 표준 라이브러리만 (snappy, BSON, WiredTiger 직접 구현). zstd, lz4 블록, 저널 재생은 미지원
- 사용: `backend/mongoaccess.py` (`from .vendor.mongodb_viewer.engine.mongo import open_dbpath`)

가져올 때의 파일 SHA-256:

```
d1a2b710cffff4e5df292a160812c0b539525e2e77a30f4f7c740cba7ef511fa *mongodb_viewer/__init__.py
36c253f24017e852660a5dd25948eb26a33f12859865a6343119d626fe0e59a2 *mongodb_viewer/source.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 *mongodb_viewer/engine/__init__.py
20983d75bf9aaa00057c04a8b6dc6963c59cab07c50bc311406009b81d786706 *mongodb_viewer/engine/mongo/__init__.py
255659c5441b7200dd1a5f59083dc2a3983ca9d9a9410163b76eccc68c52ddd8 *mongodb_viewer/engine/mongo/bsonlib.py
62bd7e6f539e91ed5b8275497e2d44f9a58a00a699bfc0ddcb06cce1fa3f6d19 *mongodb_viewer/engine/mongo/dbpath.py
8763e168a9d16527369d54d9cce97356c0c87f645982ff76b960637184369189 *mongodb_viewer/engine/mongo/intpack.py
8f6bc30e912a3f136abe8ad6a7619da08b292840147300ab905f6b817fed3d21 *mongodb_viewer/engine/mongo/oplog.py
9d83293837758580ecc0b38a3746535eab6cf2da8103ecb604aa05bcb48a964d *mongodb_viewer/engine/mongo/snappy.py
02b7b25efe4e3e1af5dcd3793d1542051bfdf3b21ceba936ef1ca44046621f93 *mongodb_viewer/engine/mongo/wtfile.py
```
