import flet as ft
from pathlib import Path
import json
import webbrowser


def generate_network_map_html(web_dir: Path, json_path: Path):
    template_path = Path(f"{web_dir}/networks_map.html")
    output_path = Path(f"{web_dir}/web_networks_map.html")

    with open(template_path, "r", encoding="utf-8") as f:
        html_template = f.read()

    with open(json_path, "r", encoding="utf-8") as f:
        ssid_data = json.load(f)

    json_as_js = json.dumps(ssid_data)
    filled_html = html_template.replace("__REPLACE_WITH_JSON__", json_as_js)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(filled_html)

    return output_path


def generate_network_stats_html(web_dir: Path, json_path: Path):
    template_path = Path(f"{web_dir}/network_stats.html")
    output_path = Path(f"{web_dir}/web_network_stats.html")

    with open(template_path, "r", encoding="utf-8") as f:
        html_template = f.read()

    with open(json_path, "r", encoding="utf-8") as f:
        stats_data = json.load(f)

    json_as_js = json.dumps(stats_data)
    filled_html = html_template.replace("__REPLACE_WITH_JSON__", json_as_js)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(filled_html)

    return output_path


class NetworkStats:
    def __init__(self, state):
        self.state = state
        self.page = state.page
        self.source_path = Path(f"{self.state.data_analysis_dir}/network_stats.json")
        self.map_source_path = Path(f"{self.state.data_analysis_dir}/extended_networks.json")

        with open(self.source_path, "r") as f:
            self.network_stats = json.load(f)

    def _build_distribution_block(self, title, icon_name, color, data_dict):
        entries = []

        def create_hoverable_row(label_str, count_str):
            container = ft.Container()
            row = ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Text(label_str, weight=ft.FontWeight.W_500),
                    ft.Text(count_str, weight=ft.FontWeight.BOLD),
                ],
            )
            container.content = row
            container.padding = 5
            container.border_radius = 5

            def on_hover(e):
                container.bgcolor = ft.Colors.ORANGE_200 if e.data == "true" else None
                container.update()

            container.on_hover = on_hover
            return container

        # Sort keys intelligently
        def sort_key(x):
            try:
                return int(x[0])
            except ValueError:
                return float("inf")

        for label, count in sorted(data_dict.items(), key=sort_key):
            label_str = f"{label} GHz" if title == "Band Distribution" else label
            entry = create_hoverable_row(label_str, str(count))
            entries.append(entry)

        return ft.Container(
            bgcolor=ft.Colors.GREY_100,
            border_radius=10,
            padding=10,
            margin=ft.margin.only(bottom=15),
            content=ft.Column(
                controls=[
                    ft.Row(
                        controls=[
                            ft.Icon(name=icon_name, color=color, size=20),
                            ft.Text(title, size=18, weight=ft.FontWeight.W_600)
                        ]
                    ),
                    ft.Divider(height=1, color=ft.Colors.GREY_300),
                    *entries
                ]
            )
        )

    def render(self):
        total_ssid = ft.Row(
            controls=[
                ft.Icon(name=ft.Icons.WIFI, size=20, color=ft.Colors.BLUE),
                ft.Text(f"Total SSID: {self.network_stats['total_ssid']}", size=20, color=ft.Colors.BLACK87),
            ]
        )

        total_aps = ft.Row(
            controls=[
                ft.Icon(name=ft.Icons.ROUTER, size=20, color=ft.Colors.BLUE),
                ft.Text(f"Total APs: {self.network_stats['total_aps']}", size=20, color=ft.Colors.BLACK87),
            ]
        )

        channel_data = {
            k: v for k, v in self.network_stats["channel_count"].items()
            if k.lower() != "null"
        }

        encryption_data = self.network_stats["encryption_count"]
        band_data = self.network_stats["band_count"]

        # Styled blocks
        channel_block = self._build_distribution_block(
            "Channel Distribution", ft.Icons.WIFI_CHANNEL, ft.Colors.BLUE, channel_data
        )
        encryption_block = self._build_distribution_block(
            "Encryption Distribution", ft.Icons.LOCK, ft.Colors.DEEP_ORANGE, encryption_data
        )
        band_block = self._build_distribution_block(
            "Band Distribution", ft.Icons.SIGNAL_WIFI_4_BAR, ft.Colors.GREEN, band_data
        )

        def open_network_map(e):
            html_path = Path(generate_network_map_html(self.state.web_pages_dir, self.map_source_path))
            webbrowser.open(Path(html_path).absolute().as_uri())

        # Button to open HTML page
        def open_graphs(e):
            html_path = Path(generate_network_stats_html(self.state.web_pages_dir, self.source_path))
            webbrowser.open(html_path.absolute().as_uri())

        open_stats_button = ft.FilledTonalButton(
            content=ft.Container(
                padding=ft.Padding(2, 2, 2, 2),
                content=ft.Row(
                    controls=[
                        ft.Icon(name=ft.Icons.SHOW_CHART_OUTLINED, color=ft.Colors.BLACK38, size=20),
                        ft.Icon(name=ft.Icons.OPEN_IN_BROWSER_OUTLINED, color=ft.Colors.BLACK38, size=20),
                        ft.Text("Open Graphs in Browser", size=20, color=ft.Colors.BLACK38)
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
            on_click=open_graphs
        )

        open_network_map_button = ft.FilledTonalButton(
            content=ft.Container(
                padding=ft.Padding(2, 2, 2, 2),
                content=ft.Row(
                    controls=[
                        ft.Icon(name=ft.Icons.HUB_OUTLINED, color=ft.Colors.BLACK38, size=20),
                        ft.Icon(name=ft.Icons.OPEN_IN_BROWSER_OUTLINED, color=ft.Colors.BLACK38, size=20),
                        ft.Text("Open Network Map in Browser", size=20, color=ft.Colors.BLACK38)
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
            on_click=open_network_map
        )

        return ft.Column(
            scroll=ft.ScrollMode.AUTO,
            expand=True,
            controls=[
                ft.Row([total_ssid, total_aps, ft.Container(expand=True), open_stats_button, open_network_map_button]),
                ft.Divider(),
                ft.Row(
                    expand=True,
                    spacing=10,
                    vertical_alignment=ft.CrossAxisAlignment.START,
                    controls=[
                        ft.Container(expand=1, content=channel_block),
                        ft.Container(expand=1, content=encryption_block),
                        ft.Container(expand=1, content=band_block),
                    ]
                )
            ]
        )
