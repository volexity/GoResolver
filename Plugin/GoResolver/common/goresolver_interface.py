"""Adaptor class to interact with the GoResolver CLI."""

import time
from pathlib import Path
from subprocess import DEVNULL, CalledProcessError, check_output
from threading import Thread
from typing import Any


class GoResolverInterface:
    """Adaptor class to interact with the GoResolver CLI."""

    class ValueThread(Thread):
        """Extension to the base Thread class to easily retrieve the called thread's return value."""

        def __init__(self, group=None, target=None, name=None, args=..., kwargs=None, *, daemon=None):
            super().__init__(group, target, name, args, kwargs, daemon=daemon)
            self._return_value: str | None = None

        def run(self) -> None:
            try:
                if self._target is not None:
                    self._return_value = self._target(*self._args, **self._kwargs)
            finally:
                del self._target, self._args, self._kwargs

        def join(self, timeout=None) -> str | None:
            super().join(timeout)
            return self._return_value

    @staticmethod
    def _run_goresolver_thread(*args: Any) -> str:  # noqa: ANN401
        """Thread method running GoResolver in a sub-processs.

        Args:
            *args: Arguments to pass the the GoResolver process.

        Retuns:
            GoResolver's report output.
        """
        return check_output(  # noqa: S603
            ["goresolver", "-q", *args],  # noqa: S607
            text=True,
            stderr=DEVNULL,
        )

    @staticmethod
    def _run_goresolver(*args: Any) -> str:  # noqa: ANN401
        """Run GoResolver in a threaded subprocess.

        Args:
            args: CLI arguments to forward to the GoResolver process.
        """
        report_data: str = ""

        try:
            goresolver_thread: GoResolverInterface.ValueThread = GoResolverInterface.ValueThread(
                target=GoResolverInterface._run_goresolver_thread, args=args
            )
            goresolver_thread.start()

            while goresolver_thread.is_alive():
                time.sleep(1)
            report_data = goresolver_thread.join()
        except CalledProcessError as e:
            print("EXCEPT", e.__class__, e)

        return report_data

    @staticmethod
    def resolve(file_path: Path, go_versions: list[str]) -> str:
        """Execute a GoResover analysis.

        Args:
            go_versions: The list of GoVersions to use during analysis.
            file_path: The path to the file to analyze.

        Retuns:
            GoResolver's report output.
        """
        return GoResolverInterface._run_goresolver("resolve", "-y", "-v", ",".join(go_versions), str(file_path))

    @staticmethod
    def install(go_versions: list[str]) -> str:
        """Install the requested Go versions.

        Args:
            go_versions: The list of Go versions to be installed.

        Returns:
            GoResolver's output.
        """
        return GoResolverInterface._run_goresolver("manage", "-i", ",".join(go_versions))

    @staticmethod
    def uninstall(go_versions: list[str]) -> str:
        """Uninstall the requested Go versions.

        Args:
            go_versions: The list of go versions to be uninstalled.

        Returns:
            GoResolver's output.
        """
        return GoResolverInterface._run_goresolver("manage", "-u", ",".join(go_versions))

    @staticmethod
    def request_versions(go_versions: list[str]) -> None:
        """Request the following go versions to be installed and uninstalls any other.

        Args:
            go_versions: The Go versions requested by the user.
        """
        GoResolverInterface.install(go_versions)
        GoResolverInterface.uninstall(
            [v for v in GoResolverInterface.get_installed_go_versions() if v not in go_versions]
        )

    @staticmethod
    def get_installed_go_versions() -> list[str]:
        """Returns the list of Go versions currently installed."""
        return check_output(["goresolver", "-q", "manage", "--list_installed"], text=True, stderr=DEVNULL).splitlines()  # noqa: S607

    @staticmethod
    def get_available_go_versions() -> list[str]:
        """Returns the list of available Go versions."""
        return check_output(["goresolver", "-q", "manage", "--list_available"], text=True, stderr=DEVNULL).splitlines()  # noqa: S607
