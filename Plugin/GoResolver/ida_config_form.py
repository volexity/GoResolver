"""GoResolver IDA Pro plugin's configuration form."""

from logging import Logger, getLogger
from pathlib import Path
from typing import Final

import ida_kernwin  # type: ignore[import-untyped,import-not-found]
from common.action_modes import ActionModes

logger: Final[Logger] = getLogger(__name__)


class IDAConfigForm(ida_kernwin.Form):
    """GoResolver IDA Pro plugin's configuration form."""

    def __init__(self, restrict: list[ActionModes] | None = None) -> None:
        """Initialize a new IDAConfigForm.

        Args:
            restrict: Disable the select action modes.
        """
        super().__init__(
            r"""STARTITEM {id:rImport}
BUTTON YES Ok
BUTTON CANCEL* Cancel
GoResolver


{FormChangeCb}
<####Analyze the current file:{rAnalyze}> | <#Report save path#Save path:{iReportSave}>
<Import a previous report:{rImport}>{cActionGroup}> | <#Report import path#Import path:{iReportImport}>
""",
            {
                "FormChangeCb": self.FormChangeCb(handler=self.OnFormChange),
                "iReportSave": self.FileInput(save=True),
                "iReportImport": self.FileInput(open=True),
                "cActionGroup": self.RadGroupControl(("rAnalyze", "rImport")),
            },
        )

        self.Compile()

        self.iReportSave.value = "*.json"
        self.iReportImport.value = "*.json"

        self.restrict: Final[list[ActionModes] | None] = restrict

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
                self.mode = ActionModes.IMPORT

            case self.rAnalyze.id:
                self.mode = ActionModes.ANALYZE
            case self.rImport.id:
                self.mode = ActionModes.IMPORT

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

    def show(self) -> bool:
        """Show the form.

        Returns: Modal result.
        """
        return self.Execute() == 1
