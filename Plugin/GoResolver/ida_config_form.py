"""GoResolver IDA Pro plugin's configuration form."""

from logging import Logger, getLogger
from pathlib import Path
from typing import Final

import ida_kernwin  # type: ignore[import-untyped,import-not-found]
from common.action_modes import ActionModes
from common.goresolver_interface import GoResolverInterface

logger: Final[Logger] = getLogger(__name__)


class EGoVersionChooserClass(ida_kernwin.Choose):
    """Embedded GO Version chooser class."""

    def __init__(self, title, content: list[str], *, flags=0):
        ida_kernwin.Choose.__init__(self, title, cols=[["GO Version", 30]], flags=flags, embedded=True)
        self.items: list[list[str]] = [[item] for item in content]

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)


class IDAConfigForm(ida_kernwin.Form):
    """GoResolver IDA Pro plugin's configuration form."""

    def __init__(self, restrict: list[ActionModes] | None = None) -> None:
        """Initialize a new IDAConfigForm.

        Args:
            restrict: Disable the select action modes.
        """
        super().__init__(
            r"""STARTITEM {id:rAnalyze}
BUTTON YES Ok
BUTTON CANCEL* Cancel
GoResolver


{FormChangeCb}
<####Analyze the current file:{rAnalyze}> | <#Report save path#Save path:{iReportSave}>
<Import a previous report:{rImport}>{cActionGroup}> | <#Report import path#Import path:{iReportImport}>

<Installed GO Versions:{cInstalledVersionsEChooser}> | <##--->:{iUninstallButton}> <##<---:{iInstallButton}> | <Available GO Versions:{cAvailableVersionsEChooser}>
""",  # noqa: E501
            {
                "FormChangeCb": self.FormChangeCb(handler=self.OnFormChange),
                "iReportSave": self.FileInput(save=True),
                "iReportImport": self.FileInput(open=True),
                "cActionGroup": self.RadGroupControl(("rAnalyze", "rImport")),
                "iUninstallButton": self.ButtonInput(self._uninstall_button),
                "iInstallButton": self.ButtonInput(self._install_button),
                "cInstalledVersionsEChooser": self.EmbeddedChooserControl(
                    EGoVersionChooserClass(
                        "E1", GoResolverInterface.get_installed_go_versions(), flags=ida_kernwin.Choose.CH_MULTI
                    )
                ),
                "cAvailableVersionsEChooser": self.EmbeddedChooserControl(
                    EGoVersionChooserClass(
                        "E2", GoResolverInterface.get_available_go_versions(), flags=ida_kernwin.Choose.CH_MULTI
                    )
                ),
            },
        )

        self.Compile()

        self.iReportSave.value = "*.json"
        self.iReportImport.value = "*.json"

        self.restrict: Final[list[ActionModes] | None] = restrict
        self._selected_go_versions: list[str] = []
        self._requested_versions: list[str] = []

    def _get_chooser_items(self, chooser) -> list[str]:
        """Get the list of items in a chooser.

        Args:
            chooser: The chooser to probe.

        Returns:
            The list of its items.
        """
        return [i[0] for i in chooser.chooser.items]

    def _get_chooser_selected_items(self, chooser) -> list[str]:
        """Get the curent chooser selection, or all items if none are selected.

        Args:
            chooser: The chooser to probe.

        Returns:
            The list of selected items.
        """
        selected: list[int] = self.GetControlValue(chooser)
        if selected:
            return [chooser.chooser.items[i][0] for i in selected]
        return [i[0] for i in chooser.chooser.items]

    def _set_chooser_items(self, chooser, items: list[str]) -> None:
        """The the chooser to use the new item list.

        Args:
            chooser: Chooser to modify.
            items: New list of item to use.
        """
        chooser.chooser.items = [[item] for item in items]
        self.RefreshField(chooser)

    def _append_chooser_items(self, chooser, items: list[str]) -> None:
        """Add items to the selected chooser.

        Args:
            chooser: Chooser to modify.
            items: List of items to add to the chooser.
        """
        new_items: list[str] = [i[0] for i in chooser.chooser.items]
        new_items.extend(i for i in items if i not in new_items)
        new_items.sort()

        self._set_chooser_items(chooser, new_items)

    def _remove_chooser_items(self, chooser, items: list[str]) -> None:
        """Remove items for the selected chooser.

        Args:
            chooser: The chooser to modify.
            items: List of items to remove from the chooser.
        """
        self._set_chooser_items(chooser, [i[0] for i in chooser.chooser.items if i[0] not in items])

    def _uninstall_button(self, _code: int = 0) -> None:
        """Remove the currently selected items from the installed version chooser."""
        selected: list[str] = self._get_chooser_selected_items(self.cInstalledVersionsEChooser)
        self._remove_chooser_items(self.cInstalledVersionsEChooser, selected)
        self._update_selection()
        self._update_requested()

    def _install_button(self, _code: int = 0) -> None:
        """Add the currently selected items to the installed version chooser."""
        items: list[str] = self._get_chooser_selected_items(self.cAvailableVersionsEChooser)
        self._append_chooser_items(self.cInstalledVersionsEChooser, items)
        self._update_selection()
        self._update_requested()

    def _enable_mode(self, mode: ActionModes, enabled: bool) -> None:
        """Set the enabled status of one of the UI's ActionModes field.

        Args:
            mode: The ActionModes field to modify.
            enabled: Wether the field should be enabled or not.
        """
        match mode:
            case ActionModes.ANALYZE:
                self.EnableField(self.rAnalyze, enabled)
            case ActionModes.IMPORT:
                self.EnableField(self.rImport, enabled)
            case _:
                msg = "Unreachable !"
                raise ValueError(msg)

    def _update_selection(self) -> None:
        """Updates the stored item selection with the currently selected items."""
        self._selected_go_versions = self._get_chooser_selected_items(self.cInstalledVersionsEChooser)

    def _update_requested(self) -> None:
        """Update the stored requested version list."""
        self._requested_versions = self._get_chooser_items(self.cInstalledVersionsEChooser)

    def OnFormChange(self, fid: int) -> int:
        """Triggered whenever any control of the form changes.

        Args:
            fid: The id of of the control that changed.

        Returns: Status code.
        """
        match fid:
            case -1:  # Init
                if self.restrict:
                    for mode in self.restrict:
                        self._enable_mode(mode, enabled=False)
                self.mode = ActionModes.ANALYZE
                self._update_selection()
                self._update_requested()

            case self.rAnalyze.id:
                self.mode = ActionModes.ANALYZE
            case self.rImport.id:
                self.mode = ActionModes.IMPORT
            case self.cInstalledVersionsEChooser.id:
                self._update_selection()

        return 1

    @property
    def mode(self) -> ActionModes:
        """Returns the current action mode of the ConfigForm.

        Returns: Current action mode.
        """
        return self._mode

    @mode.setter
    def mode(self, mode: ActionModes) -> None:
        """Sets the new action mode of the ConfigForm and toogle the appropriate input fields.

        Args:
            mode: The new action mode of the ConfigForm.
        """
        self.EnableField(self.iReportSave, (mode == ActionModes.ANALYZE))
        self.EnableField(self.iReportImport, (mode == ActionModes.IMPORT))
        self._mode: ActionModes = mode

    @property
    def report_path(self) -> Path | None:
        """Returns the value of the relevant input field relative to the current action mode.

        Returns: Path value of the relevant input field.
        """
        match self.mode:
            case ActionModes.ANALYZE:
                return Path(self.iReportSave.value).resolve() if self.iReportSave else None
            case ActionModes.IMPORT:
                return Path(self.iReportImport.value).resolve() if self.iReportImport else None
        return None

    @property
    def selected_versions(self) -> list[str]:
        """Returns the list of selected Go versions."""
        return self._selected_go_versions

    @property
    def requested_versions(self) -> list[str]:
        """Returns the list of the Go versions requested by the user."""
        return self._requested_versions

    def show(self) -> bool:
        """Show the form.

        Returns: Modal result.
        """
        return self.Execute() == 1
