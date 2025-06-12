import flet as ft
import threading
from helpers.check_update import check_for_update


class Template:
    def __init__(self, page: ft.Page, state, content_view: ft.Control, selected_index: int):
        self.page = page
        self.state = state
        self.content_view = content_view
        self.selected_index = selected_index

        self.check_update_icon = ft.Icon(name=ft.Icons.VERIFIED_OUTLINED, tooltip="Up to date", color=ft.Colors.GREEN,
                                         size=20)
        state.check_update_icon = self.check_update_icon

        self.info_progress = ft.ProgressRing(
            color=ft.Colors.ORANGE,
            width=20,
            height=20,
            stroke_width=2,
            visible=False
        )
        state.info_progress = self.info_progress

        threading.Thread(target=self._check_and_apply_update, daemon=True).start()

    def _check_and_apply_update(self):
        ahead = check_for_update()  # returns an int
        if ahead > 0:
            # schedule the UI update on the main Flet thread
            self.page.call_from_thread(self._on_update_available, ahead)

    def _on_update_available(self, ahead: int):
        # change the icon
        self.check_update_icon.name = ft.Icons.NOTIFICATIONS_OUTLINED
        self.check_update_icon.tooltip = "Update Available"
        self.check_update_icon.color = ft.Colors.ORANGE
        self.check_update_icon.update()

        # optionally pop a dialog
        dlg = ft.AlertDialog(
            title=ft.Text("🔔 Update available!"),
            content=ft.Text(f"There are {ahead} new commits upstream.\nRun `git pull`."),
            actions=[ft.TextButton("OK", on_click=lambda e: self._close_dialog(dlg))],
        )
        self.page.dialog = dlg
        dlg.open = True

        # finally refresh the page
        self.page.update()

    def _close_dialog(self, dlg):
        dlg.open = False
        self.page.update()

    def render(self):
        def on_nav_change(e):
            self.page.go(f"/{e.control.selected_index}")

        nav_rail = ft.NavigationRail(
            selected_index=self.selected_index,
            label_type=ft.NavigationRailLabelType.NONE,
            destinations=[
                ft.NavigationRailDestination(icon=ft.Icons.PATTERN_OUTLINED,
                                             selected_icon=ft.Icon(name=ft.Icons.PATTERN_OUTLINED, tooltip="Home",
                                                                   color=ft.Colors.BLUE), label="Aether"),
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
