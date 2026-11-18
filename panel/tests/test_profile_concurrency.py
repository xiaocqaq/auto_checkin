"""Persistent Chromium profiles cannot be shared by overlapping browser requests."""
import asyncio
import sys
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from panel.vendor.utils import browser as br


@pytest.fixture
def launcher(monkeypatch):
    contexts = []
    launching = asyncio.Event()
    allow_launch = asyncio.Event()
    allow_launch.set()

    class Context:
        closed = False
        pages = []

        async def close(self):
            self.closed = True

    async def launch(profile, **kwargs):
        launching.set()
        await allow_launch.wait()
        if any(not ctx.closed and ctx.profile == profile for ctx in contexts):
            raise RuntimeError('Failed to create a ProcessSingleton for your profile directory')
        ctx = Context()
        ctx.profile = profile
        contexts.append(ctx)
        return ctx

    monkeypatch.setitem(sys.modules, 'cloakbrowser', SimpleNamespace(launch_persistent_context_async=launch))
    monkeypatch.setattr(br, 'get_playwright_proxy', lambda **_: None)
    monkeypatch.delenv('CHECKIN_BROWSER_PROXY', raising=False)
    return SimpleNamespace(contexts=contexts, launching=launching, allow_launch=allow_launch)


def settings(path):
    return br.BrowserLoginSettings(
        headless=True, humanize=False, wait_timeout_ms=1000, profile_dir=path,
        cloakbrowser_binary_path=None, persist_profile=True,
    )


async def test_same_profile_rejected_until_context_closed(tmp_path, launcher):
    config = settings(tmp_path / 'github' / 'account')
    first = await br.launch_login_context(config)
    try:
        with pytest.raises(RuntimeError, match='正在.*使用'):
            await br.launch_login_context(config)
        assert len(launcher.contexts) == 1
        assert first.pages == []
    finally:
        await first.close()
    second = await br.launch_login_context(config)
    await second.close()
    assert len(launcher.contexts) == 2


@pytest.mark.parametrize('unknown', ['bad-pid', 'permission'])
async def test_unknown_singleton_owner_is_not_deleted(tmp_path, launcher, monkeypatch, unknown):
    config = settings(tmp_path / 'account')
    config.profile_dir.mkdir()
    pid = 'unknown' if unknown == 'bad-pid' else '12345'
    lock = config.profile_dir / 'SingletonLock'
    lock.symlink_to(f'{socket.gethostname()}-{pid}')
    if unknown == 'permission':
        original = Path.read_bytes
        def denied(path):
            if str(path) == '/proc/12345/cmdline':
                raise PermissionError('not permitted to inspect owner')
            return original(path)
        monkeypatch.setattr(Path, 'read_bytes', denied)
    with pytest.raises(RuntimeError, match='正在.*使用'):
        await br.launch_login_context(config)
    assert lock.is_symlink()
    assert not launcher.contexts


async def test_different_profiles_can_launch_together(tmp_path, launcher):
    first = await br.launch_login_context(settings(tmp_path / 'one'))
    second = await br.launch_login_context(settings(tmp_path / 'two'))
    await first.close()
    await second.close()


async def test_launch_cancellation_releases_lease(tmp_path, launcher):
    config = settings(tmp_path / 'account')
    launcher.allow_launch.clear()
    task = asyncio.create_task(br.launch_login_context(config))
    await launcher.launching.wait()
    task.cancel()
    launcher.allow_launch.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    context = await br.launch_login_context(config)
    await context.close()


async def test_launch_cancel_after_allocation_closes_context(tmp_path, launcher, monkeypatch):
    config = settings(tmp_path / 'account')
    allocated = asyncio.Event()
    finish_launch = asyncio.Event()
    raw = SimpleNamespace(closed=False, pages=[])

    async def close():
        raw.closed = True

    raw.close = close
    async def launch(*_, **__):
        allocated.set()
        await finish_launch.wait()
        return raw

    monkeypatch.setattr(sys.modules['cloakbrowser'], 'launch_persistent_context_async', launch)
    task = asyncio.create_task(br.launch_login_context(config))
    await allocated.wait()
    task.cancel()
    finish_launch.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert raw.closed, 'allocated browser must close even when the caller cancels startup'


async def test_close_cancellation_keeps_lease_until_cleanup(tmp_path, launcher):
    config = settings(tmp_path / 'account')
    context = await br.launch_login_context(config)
    closing = asyncio.Event()
    finish = asyncio.Event()
    done = asyncio.Event()
    raw = launcher.contexts[0]

    async def close():
        closing.set()
        await finish.wait()
        raw.closed = True
        done.set()

    raw.close = close
    task = asyncio.create_task(context.close())
    await closing.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(RuntimeError, match='正在.*使用'):
        await br.launch_login_context(config)
    finish.set()
    await done.wait()
    await context.close()
    next_context = await br.launch_login_context(config)
    await next_context.close()


async def test_live_and_foreign_singleton_locks_are_preserved(tmp_path, launcher, monkeypatch):
    for owner in [f'{socket.gethostname()}-1234', 'another-host-1234']:
        config = settings(tmp_path / owner)
        config.profile_dir.mkdir()
        lock = config.profile_dir / 'SingletonLock'
        lock.symlink_to(owner)
        monkeypatch.setattr(br, '_pid_alive_in_this_container', lambda _: True)
        with pytest.raises(RuntimeError, match='正在.*使用'):
            await br.launch_login_context(config)
        assert lock.is_symlink()
    assert not launcher.contexts


async def test_confirmed_dead_singleton_lock_is_cleaned(tmp_path, launcher, monkeypatch):
    config = settings(tmp_path / 'account')
    config.profile_dir.mkdir()
    monkeypatch.setattr(br, '_pid_alive_in_this_container', lambda _: False)
    (config.profile_dir / 'SingletonLock').symlink_to(f'{socket.gethostname()}-1234')
    context = await br.launch_login_context(config)
    await context.close()
    assert not (config.profile_dir / 'SingletonLock').is_symlink()


def test_windows_lease_without_fcntl_is_nonblocking_and_released_on_close(tmp_path, monkeypatch):
    """Exercise the Windows import path on POSIX without changing os.name globally."""
    import errno
    import os
    fcntl = pytest.importorskip('fcntl')
    calls = []

    def locking(fd, mode, count):
        assert mode == 2, 'LK_NBLCK must fail immediately instead of waiting'
        assert count == 1 and os.lseek(fd, 0, os.SEEK_CUR) == 0
        calls.append(fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise OSError(errno.EACCES, 'simulated Windows lock contention') from None

    monkeypatch.setitem(sys.modules, 'fcntl', None)
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(LK_NBLCK=2, locking=locking))
    profile = tmp_path / 'account'
    first = br._acquire_profile_lease(profile)
    try:
        with pytest.raises(br.ProfileBusyError, match='正在.*使用'):
            br._acquire_profile_lease(profile)
        other = br._acquire_profile_lease(tmp_path / 'other')
        other.close()
    finally:
        first.close()
    with br._acquire_profile_lease(profile):
        pass
    assert len(calls) == 4
