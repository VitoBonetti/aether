import flet as ft
from flet import FilePickerResultEvent
from utils.load_and_merge_pcap import load_and_merge_pcap
from utils.extract_networks import extract_networks
from utils.extract_probes import extract_probes
from utils.extract_handshakes import extract_handshakes, group_handshakes
from helpers.network_stats import network_stats


class AetherView:
    def __init__(self, state):
        self.state = state
        self.page = state.page

    def render(self):
        aether_title = ft.Text("Home", theme_style=ft.TextThemeStyle.TITLE_LARGE, color=ft.Colors.BLACK87)

        file_picker = ft.FilePicker(on_result=lambda e: on_file_picker_result(e, self.page))
        self.page.overlay.append(file_picker)

        def pick_files(e):
            file_picker.pick_files(allow_multiple=True, allowed_extensions=["pcap"])

        def on_file_picker_result(e: FilePickerResultEvent, page: ft.Page):
            if e.files:
                self.state.info_progress.visible = True
                paths = [file.path for file in e.files]
                all_merged_pcap = load_and_merge_pcap(paths)
                extract_networks(all_merged_pcap, self.state.data_analysis_dir)
                network_stats(self.state.data_analysis_dir)
                extract_probes(all_merged_pcap, self.state.data_analysis_dir)
                handshakes = extract_handshakes(all_merged_pcap)
                group_handshakes(handshakes, self.state.data_analysis_dir)

                self.state.info_progress.visible = False
                self.page.snack_bar.content = ft.Row(
                    controls=[
                        ft.Icon(name=ft.Icons.WARNING, color=ft.Colors.BLACK87, size=20),
                        ft.Text("No data found in raw_data directory.", color=ft.Colors.BLACK87, size=20)
                    ]
                )
                self.page.snack_bar.bgcolor = ft.Colors.ORANGE_200
                self.page.snack_bar.open = True
                self.page.update()

        pick_files_button = ft.FilledTonalButton(
            content=ft.Container(
                padding=ft.Padding(2, 2, 2, 2),
                content=ft.Row(
                    controls=[
                        ft.Icon(name=ft.Icons.UPLOAD_FILE, color=ft.Colors.BLACK38, size=20),
                        ft.Text("Select PCAPs", size=20, color=ft.Colors.BLACK38)
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

        view_content = ft.Container(
            expand=True,
            padding=5,
            content=ft.Column(
                controls=[
                    aether_title,
                    ft.Divider(),
                    ft.Row([pick_files_button])
                ],
                expand=True
            )
        )

        return view_content
