from __future__ import annotations

import logging
import os
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

log = logging.getLogger("mfa.handles")


class Busy(Exception):
    pass


class Cancelled(Exception):
    pass


class Handle:
    def __init__(self, key: str, obj):
        self.key = key
        self.obj = obj
        self.refs = 0
        self.retired = False
        self.cancelled = False
        self.lock = threading.Lock()

    def check(self) -> None:
        if self.cancelled:
            raise Cancelled("증거가 교체, 삭제되는 중입니다")


def _under(key: str, prefix: str) -> bool:
    return key == prefix or key.startswith(prefix.rstrip("/" + "\\") + os.sep)


class Registry:
    def __init__(self, name: str, size: int, opener: Callable[[Path], object], closer: Callable[[object], None]):
        self.name, self.size, self._opener, self._closer = name, size, opener, closer
        self._entries: "OrderedDict[str, Handle]" = OrderedDict()
        self._busy: set[Handle] = set()
        self._opening: set[str] = set()
        self._blocked: dict[str, int] = {}
        self._cond = threading.Condition()

    def _is_blocked(self, key: str) -> bool:
        return any(_under(key, p) for p in self._blocked)

    def _close(self, h: Handle) -> None:
        if h.obj is None:
            return
        try:
            self._closer(h.obj)
        except Exception:
            log.warning("%s 닫기 실패: %s", self.name, h.key, exc_info=True)

    def _retire(self, h: Handle, cancel: bool = False) -> None:
        h.retired = True
        h.cancelled = h.cancelled or cancel
        if h.refs == 0:
            self._close(h)
        else:
            self._busy.add(h)

    @contextmanager
    def use(self, path: Path) -> Iterator[Handle]:
        key = str(Path(path).resolve())
        h = self._acquire(key, Path(path))
        try:
            yield h
        finally:
            with self._cond:
                h.refs -= 1
                if h.retired and h.refs == 0:
                    self._busy.discard(h)
                    self._close(h)
                    self._cond.notify_all()

    def _acquire(self, key: str, path: Path) -> Handle:
        with self._cond:
            while True:
                if self._is_blocked(key):
                    raise Busy("증거를 교체, 삭제하는 중입니다. 잠시 후 다시 시도하세요.")
                h = self._entries.get(key)
                if h is not None:
                    self._entries.move_to_end(key)
                    h.refs += 1
                    return h
                if key not in self._opening:
                    self._opening.add(key)
                    break
                self._cond.wait()
        try:
            obj = self._opener(path)
        except BaseException:
            with self._cond:
                self._opening.discard(key)
                self._cond.notify_all()
            raise
        with self._cond:
            self._opening.discard(key)
            self._cond.notify_all()
            h = Handle(key, obj)
            if self._is_blocked(key):
                self._close(h)
                raise Busy("증거를 교체, 삭제하는 중입니다. 잠시 후 다시 시도하세요.")
            h.refs = 1
            self._entries[key] = h
            while len(self._entries) > self.size:
                _, old = self._entries.popitem(last=False)
                self._retire(old)
            return h

    def blocked(self, path: Path) -> bool:
        if not self._blocked:
            return False
        with self._cond:
            return self._is_blocked(str(path))

    def forget(self, prefix: Path) -> None:
        p = str(Path(prefix).resolve())
        with self._cond:
            for k in [k for k in self._entries if _under(k, p)]:
                self._retire(self._entries.pop(k))

    @contextmanager
    def exclusive(self, prefix: Path, timeout: float = 30.0) -> Iterator[None]:
        p = str(Path(prefix).resolve())
        with self._cond:
            self._blocked[p] = self._blocked.get(p, 0) + 1
            for k in [k for k in self._entries if _under(k, p)]:
                self._retire(self._entries.pop(k), cancel=True)
            for h in self._busy:
                if _under(h.key, p):
                    h.cancelled = True
            end = time.monotonic() + timeout
            while any(_under(h.key, p) for h in self._busy) or any(_under(k, p) for k in self._opening):
                left = end - time.monotonic()
                if left <= 0:
                    log.warning("%s: %s 사용 중인 핸들이 반납되지 않았습니다 (계속 진행)", self.name, p)
                    break
                self._cond.wait(left)
        try:
            yield
        finally:
            with self._cond:
                self._blocked[p] -= 1
                if not self._blocked[p]:
                    del self._blocked[p]
                self._cond.notify_all()
