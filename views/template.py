import flet as ft
import threading
from helpers.check_update import check_for_update


class Template:
    def __init__(self, page: ft.Page, state, content_view: ft.Control, selected_index: int):
        self.page = page
        self.state = state
        self.content_view = content_view
        self.selected_index = selected_index
        self.check_update_icon = ft.Icon(name=ft.Icons.VERIFIED_OUTLINED, tooltip="Up to date", color=ft.Colors.BLUE, size=20)
        state.check_update_icon = self.check_update_icon
        self.info_progress = ft.ProgressRing(
            color=ft.Colors.ORANGE,
            width=20,
            height=20,
            stroke_width=2,
            visible=False
        )
        state.info_progress = self.info_progress

        self._update_check_started = False

    def render(self):
        if not self._update_check_started:
            if threading.Thread(target=check_for_update, daemon=True).start():
                self.check_update_icon.name = ft.Icons.NOTIFICATIONS_OUTLINED
                self.check_update_icon.tooltip = "Update Available"
                self.check_update_icon.color = ft.Colors.ORANGE
                self.check_update_icon.update()
                self._update_check_started = True

        def on_nav_change(e):
            self.page.go(f"/{e.control.selected_index}")

        nav_rail = ft.NavigationRail(
            selected_index=self.selected_index,
            label_type=ft.NavigationRailLabelType.NONE,
            destinations=[
                ft.NavigationRailDestination(icon=ft.Icons.PATTERN_OUTLINED,
                                             selected_icon=ft.Icon(name=ft.Icons.PATTERN_OUTLINED, tooltip="Home", color=ft.Colors.BLUE),
                                             label="Aether"),
                ft.NavigationRailDestination(icon=ft.Icons.WIFI_OUTLINED,
                                             selected_icon=ft.Icon(name=ft.Icons.WIFI_OUTLINED, tooltip="Networks", color=ft.Colors.BLUE),
                                             label="Network Groups"),
                ft.NavigationRailDestination(icon=ft.Icons.ANALYTICS_OUTLINED,
                                             selected_icon=ft.Icon(name=ft.Icons.ANALYTICS_OUTLINED, tooltip="Network Stats", color=ft.Colors.BLUE),
                                             label="Network Stats"),
                ft.NavigationRailDestination(icon=ft.Icons.CIRCLE,
                                             selected_icon=ft.Icon(name=ft.Icons.CIRCLE, tooltip="View3", color=ft.Colors.BLUE),
                                             label="View3"),
                ft.NavigationRailDestination(icon=ft.Icons.CIRCLE,
                                             selected_icon=ft.Icon(name=ft.Icons.CIRCLE, tooltip="View4", color=ft.Colors.BLUE),
                                             label="View4"),
                ft.NavigationRailDestination(icon=ft.Icons.CIRCLE,
                                             selected_icon=ft.Icon(name=ft.Icons.CIRCLE, tooltip="View5, color=ft.Colors.BLUE"),
                                             label="View5"),
            ],
            on_change=on_nav_change,
        )

        main_title = ft.Row(
            controls=[
                ft.Text(
                    spans=[
                        ft.TextSpan(
                            "Aether",
                            ft.TextStyle(
                                weight=ft.FontWeight.BOLD,
                                color=ft.Colors.BLACK87,
                            )
                        )
                    ],
                    theme_style=ft.TextThemeStyle.TITLE_LARGE
                ),
                ft.Container(expand=True),
                self.info_progress,
                self.check_update_icon
            ]
        )

        template_layout = ft.Row(
            expand=True,
            vertical_alignment=ft.CrossAxisAlignment.STRETCH,
            controls=[
                ft.Container(width=60, content=nav_rail),
                ft.VerticalDivider(width=1, thickness=1, color=ft.Colors.ORANGE),
                ft.Container(
                    expand=True,
                    padding=10,
                    content=ft.Column(
                        [
                            main_title,
                            ft.Divider(thickness=1, color=ft.Colors.ORANGE),
                            self.content_view,
                        ]),

                )
            ]
        )

        return ft.Column(
            expand=True,
            controls=[
                template_layout,
                self.page.snack_bar
            ]
        )
