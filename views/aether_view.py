import flet as ft
from flet import FilePickerResultEvent
from utils.load_and_merge_pcap import load_and_merge_pcap
from utils.extract_networks import extract_networks
from utils.extract_probes import extract_probes
from utils.extract_handshakes import extract_handshakes, group_handshakes
from helpers.network_stats import network_stats
import sys
import git
import threading


class StdoutToTextField:
    def __init__(self, text_field: ft.TextField, page: ft.Page):
        self.text_field = text_field
        self.page = page
        self._buffer = ""

    def write(self, data: str):
        # buffer up until newlines
        self._buffer += data
        if "\n" in self._buffer:
            lines = self._buffer.split("\n")
            # keep any partial line in buffer
            self._buffer = lines.pop()
            for line in lines:
                # append and scroll
                self.text_field.value += line + "\n"
            self.text_field.update()
            self.page.update()

    def flush(self):
        # flush any remaining text
        if self._buffer:
            self.text_field.value += self._buffer
            self._buffer = ""
            self.text_field.update()
            self.page.update()


class AetherView:
    def __init__(self, state):
        self.state = state
        self.page = state.page

    def check_for_update(self):
        try:
            repo = git.Repo(search_parent_directories=True)
            origin = repo.remote('origin')
            origin.fetch()

            ahead = sum(1 for _ in repo.iter_commits("HEAD..origin/master"))

            if ahead > 0:
                dlg = ft.AlertDialog(
                    title=ft.Text("Updates are available!"),
                    content=ft.Text(f"There are new commits upstream.\nRun `git pull` to grab them."),
                    actions=[ft.TextButton("OK", on_click=lambda e: self.close_update_dialog(e, dlg, self.page))]
                )
                self.page.dialog = dlg
                dlg.open = True
                self.state.check_update_icon.name = ft.Icons.NOTIFICATIONS
                self.state.check_update_icon.tooltip = "Update Available"
                self.state.check_update_icon.color = ft.Colors.ORANGE
                self.state.check_update_icon.update()
                self.page.update()
        except Exception as e:
            print("Update-check error:", e)

    def close_update_dialog(self, e, dlg, page):
        dlg.open = False
        page.update()

    def render(self):
        aether_title = ft.Text("Home", theme_style=ft.TextThemeStyle.TITLE_LARGE, color=ft.Colors.BLACK87)

        file_picker = ft.FilePicker(on_result=lambda e: on_file_picker_result(e, self.page))
        self.page.overlay.append(file_picker)

        def pick_files(e):
            file_picker.pick_files(allow_multiple=True, allowed_extensions=["pcap"])

        def on_file_picker_result(e: FilePickerResultEvent, page: ft.Page):
            if e.files:
                self.state.info_progress.visible = True

                self.logs_text_field.value = ""
                writer = StdoutToTextField(self.logs_text_field, page)
                old_stdout = sys.stdout
                sys.stdout = writer
                try:
                    paths = [file.path for file in e.files]
                    all_merged_pcap = load_and_merge_pcap(paths)
                    extract_networks(all_merged_pcap, self.state.data_analysis_dir)
                    network_stats(self.state.data_analysis_dir)
                    extract_probes(all_merged_pcap, self.state.data_analysis_dir)
                    handshakes = extract_handshakes(all_merged_pcap)
                    group_handshakes(handshakes, self.state.data_analysis_dir)
                finally:
                    # restore
                    sys.stdout = old_stdout
                    writer.flush()

                self.state.info_progress.visible = False
                self.page.snack_bar.content = ft.Row(
                    controls=[
                        ft.Icon(name=ft.Icons.TASK_ALT_OUTLINED, color=ft.Colors.BLACK87, size=20),
                        ft.Text("Pcap uploaded successfully!", color=ft.Colors.BLACK87, size=20)
                    ]
                )
                self.page.snack_bar.bgcolor = ft.Colors.GREEN_200
                self.page.snack_bar.open = True
                self.page.update()

        pick_files_button = ft.FilledTonalButton(
            content=ft.Container(
                padding=ft.Padding(2, 2, 2, 2),
                content=ft.Row(
                    controls=[
                        ft.Icon(name=ft.Icons.UPLOAD_FILE, color=ft.Colors.BLACK38, size=16),
                        ft.Text("Select PCAPs", size=16, color=ft.Colors.BLACK38)
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=2
                )
            ),
            style=ft.ButtonStyle(
                bgcolor={
                    ft.ControlState.HOVERED: ft.Colors.ORANGE_100,
                    ft.ControlState.DEFAULT: ft.Colors.SURFACE,
                }
            ),
            on_click=pick_files
        )

        logs_text_field = ft.TextField(
            multiline=True,
            min_lines=25,
            max_lines=25,
            read_only=True,
            border_radius=10,
            border_color=ft.Colors.ORANGE_100,
            border_width=2,
            filled=True,
            expand=True,
            text_align=ft.TextAlign.START,
            text_style=ft.TextStyle(size=10, font_family="Cascadia Code"),
            bgcolor=ft.Colors.GREY_100
        )

        self.logs_text_field = logs_text_field

        view_content = ft.Container(
            expand=True,
            padding=5,
            content=ft.Column(
                controls=[
                    ft.Row([pick_files_button]),
                    logs_text_field,
                ],
                expand=True
            )
        )

        return view_content
