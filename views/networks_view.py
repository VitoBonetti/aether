import flet as ft
from helpers.signal_icons import signal_icon


class NetworksView:
    def __init__(self, state, networks, networks_stats, page_size=7):
        self.state = state
        self.page = state.page
        self.networks = networks
        self.page_size = page_size
        self.page_index = 0
        self.sort_key = "ap_count"  # or "ssid"
        self.reverse = False

    def render(self):
        ssids = list(self.networks.keys())
        if self.sort_key == "ssid":
            ssids.sort(reverse=self.reverse)
        else:
            ssids.sort(key=lambda s: len(self.networks[s]), reverse=self.reverse)

        start = self.page_index * self.page_size
        page_ssids = ssids[start:start + self.page_size]

        # tiles = []
        # for ssid in page_ssids:
        #     entries = self.networks[ssid]
        #     label = ssid or "<Hidden SSID>"
        #     cards = []
        #     for ap in entries:
        #         card = ft.Card(
        #             expand=1,
        #             elevation=2,
        #             margin=ft.Margin(5, 5, 5, 5),
        #             content=ft.Container(
        #                 padding=ft.Padding(8, 0, 8, 0),
        #                 bgcolor=ft.Colors.BLUE_50,
        #                 border_radius=6,
        #                 border=ft.border.all(1, ft.Colors.ORANGE_100),
        #                 content=ft.Column(
        #                     spacing=10,
        #                     controls=[
        #                         ft.Row(
        #                             spacing=10,
        #                             controls=[
        #                                 ft.Icon(ft.Icons.ROUTER, size=16, color=ft.Colors.BLUE_900),
        #                                 ft.Text(ap["bssid"], size=14, font_family="Courier")
        #                             ]
        #                         ),
        #                         ft.Row([ft.Icon(name=ft.Icons.WIFI_CHANNEL, size=16, tooltip="Channel"),  ft.Text(f"Channel: {ap.get('channel')}", size=14, color=ft.Colors.BLACK87)]),
        #                         ft.Row([signal_icon(ap.get("signal")), ft.Text(f"Signal: {ap.get('signal')} dBm" if ap.get('signal') is not None else None, size=14, color=ft.Colors.BLACK87)]),
        #                         ft.Row([ft.Icon(name=ft.Icons.NETWORK_CHECK, size=16, tooltip="Band"), ft.Text(f"Band: {ap.get('band')} Ghz" if ap.get('band') is not None else None, size=14, color=ft.Colors.BLACK87)]),
        #                         ft.Row([ft.Icon(name=ft.Icons.KEY, size=16, tooltip="Encryption"), ft.Text(f"Encryption: {ap.get('encryption')[0]}" if ap.get('encryption') else None, size=14, color=ft.Colors.BLACK87)]),
        #                         ft.Row([ft.Icon(name=ft.Icons.PREVIEW, size=16, tooltip="Last Seen"), ft.Text(f"Last Seen: {ap.get('last_seen')}" if ap.get('last_seen') else None, size=14, color=ft.Colors.BLACK87)]),
        #
        #
        #                     ]
        #                 )
        #             )
        #         )
        #         cards.append(card)
        #
        #     # chunk into rows of max 3 cards
        #     rows = [
        #         ft.Row(controls=cards[i:i + 3], spacing=10)
        #         for i in range(0, len(cards), 3)
        #     ]
        #
        #     tile = ft.ExpansionTile(
        #         leading=ft.Icon(ft.Icons.WIFI, size=24, color=ft.Colors.BLUE_400),
        #         title=ft.Text(label, size=16, weight=ft.FontWeight.W_600),
        #         subtitle=ft.Text(f"{len(entries)} Access Point(s)", italic=True, size=11,
        #                          color=ft.Colors.BLUE_GREY_500),
        #         # replace ListView with our grid
        #         controls=rows,
        #         collapsed_icon_color=ft.Colors.BLUE,
        #         icon_color=ft.Colors.GREEN,
        #         collapsed_bgcolor=ft.Colors.GREEN_50,
        #         bgcolor=ft.Colors.GREEN_50,
        #         tile_padding=ft.Padding(8, 8, 8, 8)
        #     )
        #
        #     tiles.append(tile)
        tiles = []
        for ssid in page_ssids:
            entries = self.networks[ssid]
            label = ssid or "<Hidden SSID>"
            tables = []
            for ap in entries:
                table = ft.DataRow(
                    cells=[
                        ft.DataCell(
                            ft.Container(
                                alignment=ft.alignment.center_left,
                                content=ft.Text(ap["bssid"], size=14, color=ft.Colors.BLACK87, font_family="Courier")
                            ),

                        ),
                        ft.DataCell(
                            ft.Container(
                                alignment=ft.alignment.center_left,
                                content=ft.Text(f"{ap.get('channel')}", size=14, color=ft.Colors.BLACK87, font_family="Courier")
                            ),

                        ),

                        ft.DataCell(
                            ft.Container(
                                alignment=ft.alignment.center_left,
                                content=ft.Text(f"{ap.get('signal')} dBm" if ap.get('signal') is not None else None, size=14, color=ft.Colors.BLACK87, font_family="Courier")
                            ),

                        ),
                        ft.DataCell(
                            ft.Container(
                                alignment=ft.alignment.center_left,
                                content=ft.Text(f"{ap.get('band')} Ghz" if ap.get('band') is not None else None, size=14, color=ft.Colors.BLACK87, font_family="Courier")
                            ),

                        ),
                        ft.DataCell(
                            ft.Container(
                                alignment=ft.alignment.center_left,
                                content=ft.Text(f"{ap.get('encryption')[0]}" if ap.get('encryption') else None, size=14, color=ft.Colors.BLACK87, font_family="Courier")
                            ),

                        ),
                        ft.DataCell(
                            ft.Container(
                                alignment=ft.alignment.center_left,
                                content=ft.Text(f"{ap.get('last_seen')}" if ap.get('last_seen') else None, size=14, color=ft.Colors.BLACK87, font_family="Courier")
                            ),

                        ),
                        ft.DataCell(
                            ft.Container(
                                alignment=ft.alignment.center_left,
                                content=ft.Column(
                                    spacing=5,
                                    controls=[
                                        ft.Text(
                                            f"{client['mac']} ({client['signal']} dBm)",
                                            size=13,
                                            font_family="Courier",
                                            color=ft.Colors.BLACK87
                                        )
                                        for client in ap.get("clients", [])
                                    ] or [ft.Text(" ", size=13, font_family="Courier", italic=True, color=ft.Colors.BLACK87)]
                                )
                            ),

                        )
                    ]
                )
                tables.append(table)

            tile = ft.ExpansionTile(
                leading=ft.Icon(ft.Icons.WIFI, size=24, color=ft.Colors.BLUE_400),
                title=ft.Text(label, size=16, weight=ft.FontWeight.W_600),
                subtitle=ft.Text(f"{len(entries)} Access Point(s)", italic=True, size=11,
                                 color=ft.Colors.BLUE_GREY_500),
                collapsed_icon_color=ft.Colors.BLUE,
                icon_color=ft.Colors.GREEN,
                collapsed_bgcolor=ft.Colors.GREEN_50,
                bgcolor=ft.Colors.GREEN_50,
                tile_padding=ft.Padding(8, 8, 8, 8),
                controls=[
                    ft.DataTable(
                        expand=True,
                        width=float("inf"),
                        column_spacing=10,
                        heading_row_height=40,
                        columns=[
                            ft.DataColumn(
                                ft.Container(
                                    alignment=ft.alignment.center_left,
                                    content=ft.Row([ft.Icon(ft.Icons.ROUTER, size=16, color=ft.Colors.BLUE_900),
                                                    ft.Text("APs", size=14, font_family="Courier")])
                                )
                            ),
                            ft.DataColumn(
                                ft.Container(
                                    alignment=ft.alignment.center,
                                    content=ft.Row([ft.Icon(name=ft.Icons.WIFI_CHANNEL, size=16, tooltip="Channel"),
                                                    ft.Text("Channel", size=14, color=ft.Colors.BLACK87)])
                                )
                            ),
                            ft.DataColumn(
                                ft.Container(
                                    alignment=ft.alignment.center,
                                    content=ft.Row([signal_icon(ap.get("signal")),
                                                    ft.Text("Signal", size=14, color=ft.Colors.BLACK87)])
                                )
                            ),
                            ft.DataColumn(
                                ft.Container(
                                    alignment=ft.alignment.center,
                                    content=ft.Row([ft.Icon(name=ft.Icons.NETWORK_CHECK, size=16, tooltip="Band"),
                                                    ft.Text("Band", size=14, color=ft.Colors.BLACK87)])
                                )
                            ),
                            ft.DataColumn(
                                ft.Container(
                                    alignment=ft.alignment.center,
                                    content=ft.Row([ft.Icon(name=ft.Icons.KEY, size=16, tooltip="Encryption"),
                                                    ft.Text("Encryption", size=14, color=ft.Colors.BLACK87)])
                                )
                            ),
                            ft.DataColumn(
                                ft.Container(
                                    alignment=ft.alignment.center,
                                    content=ft.Row([ft.Icon(name=ft.Icons.PREVIEW, size=16, tooltip="Last Seen"),
                                                    ft.Text("Last Seen", size=14, color=ft.Colors.BLACK87)])
                                )
                            ),
                            ft.DataColumn(
                                ft.Container(
                                    alignment=ft.alignment.center_right,
                                    content=ft.Row([ft.Icon(name=ft.Icons.COMPUTER, size=16, tooltip="Clients"),
                                                    ft.Text("Clients", size=14, color=ft.Colors.BLACK87)])
                                )
                            )
                        ],
                        rows=tables
                    )
                ]
            )

            tiles.append(tile)

        # pagination controls
        total_pages = (len(ssids) - 1) // self.page_size + 1
        pager = ft.Row(
            controls=[
                ft.IconButton(ft.Icons.FIRST_PAGE, on_click=self.first_page, tooltip="First Page"),
                ft.IconButton(ft.Icons.ARROW_BACK, on_click=self.prev_page, tooltip="Previous Page"),
                ft.Text(f"Page {self.page_index + 1} of {total_pages}"),
                ft.IconButton(ft.Icons.ARROW_FORWARD, on_click=self.next_page, tooltip="Next Page"),
                ft.IconButton(ft.Icons.LAST_PAGE, on_click=self.last_page, tooltip="Last Page"),
            ],
            alignment=ft.MainAxisAlignment.CENTER
        )

        # sort controls
        sort_buttons = ft.Row(
            controls=[
                ft.FilledTonalButton(
                    content=ft.Container(
                        padding=ft.Padding(2, 2, 2, 2),
                        content=ft.Text("Sort by SSID", size=20, color=ft.Colors.BLACK38)
                    ),
                    style=ft.ButtonStyle(
                        bgcolor={
                            ft.ControlState.HOVERED: ft.Colors.ORANGE_100,
                            ft.ControlState.DEFAULT: ft.Colors.SURFACE,
                        }
                    ),
                    on_click=lambda e: self.set_sort('ssid')
                ),
                ft.FilledTonalButton(
                    content=ft.Container(
                        padding=ft.Padding(2, 2, 2, 2),
                        content=ft.Text("Sort by AP Count", size=20, color=ft.Colors.BLACK38)
                    ),
                    style=ft.ButtonStyle(
                        bgcolor={
                            ft.ControlState.HOVERED: ft.Colors.ORANGE_100,
                            ft.ControlState.DEFAULT: ft.Colors.SURFACE,
                        }
                    ),
                    on_click=lambda e: self.set_sort('ap_count')
                ),
                ft.IconButton(
                    ft.Icons.SORT,
                    on_click=lambda e: self.toggle_reverse(),
                    tooltip="Ascending/Descending",
                    style=ft.ButtonStyle(
                        bgcolor={
                            ft.ControlState.HOVERED: ft.Colors.ORANGE_100,
                            ft.ControlState.DEFAULT: ft.Colors.SURFACE,
                        }
                    )
                ),
                ft.FilledTonalButton(
                    content=ft.Container(
                        padding=ft.Padding(2, 2, 2, 2),
                        content=ft.Text("Network Stats", size=20, color=ft.Colors.BLACK38)
                    ),
                    style=ft.ButtonStyle(
                        bgcolor={
                            ft.ControlState.HOVERED: ft.Colors.ORANGE_100,
                            ft.ControlState.DEFAULT: ft.Colors.SURFACE,
                        }
                    ),
                    on_click=lambda e: self.page.go("/2")
                )
            ],
            spacing=10
        )

        return ft.Column(
            controls=[sort_buttons, *tiles, pager],
            scroll=ft.ScrollMode.AUTO,
            expand=True
        )

    def set_sort(self, key):
        self.sort_key = key
        self.page_index = 0
        self.state.route_change(None)

    def toggle_reverse(self):
        self.reverse = not self.reverse
        self.state.route_change(None)

    def prev_page(self, e):
        if self.page_index > 0:
            self.page_index -= 1
            self.state.route_change(None)

    def next_page(self, e):
        total = len(self.networks)
        total_pages = (total - 1) // self.page_size + 1
        if self.page_index < total_pages - 1:
            self.page_index += 1
            self.state.route_change(None)

    def first_page(self, e):
        if self.page_index != 0:
            self.page_index = 0
            self.state.route_change(None)

    def last_page(self, e):
        total = len(self.networks)
        total_pages = (total - 1) // self.page_size + 1
        if self.page_index != total_pages - 1:
            self.page_index = total_pages - 1
            self.state.route_change(None)
