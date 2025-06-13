import flet as ft
from state import State
from views.template import Template
from views.aether_view import AetherView
from views.networks_view import NetworksView
from views.networks_stats_view import NetworkStats
from pathlib import Path
import json


def main(page: ft.Page):
    page.title = "Aether v0.1"
    page.scroll = ft.ScrollMode.AUTO
    page.theme = ft.Theme(color_scheme_seed=ft.Colors.BLUE)
    page.window_maximized = True
    page.window_resizable = True
    page.snack_bar = ft.SnackBar(content=ft.Text(""), open=False)

    state = State()
    state.page = page
    page.state = state

    networks_file = Path(f'{page.state.data_analysis_dir}/extended_networks.json')
    networks_stats_file = Path(f'{page.state.data_analysis_dir}/network_stats.json')

    # one inner‐view instance per route
    state.view_instances = {}
    # one rendered inner‐view control per route
    state.view_contents = {}

    template = Template(page, state, content_view=None, selected_index=0)
    state.template_page = template

    route_map = {
        "/": ("Aether", AetherView),
        "/1": ("Networks", NetworksView),
        "/2": ("Networks Stats", NetworkStats),
        "/3": ("PlaceHolder3", AetherView),
        "/4": ("PlaceHolder4", AetherView),
        "/5": ("PlaceHolder5", AetherView)
    }

    def route_change(e):
        route = page.route or "/"
        title, ViewCls = route_map.get(route, ("Aether", AetherView))
        state.current_view_title = title

        if route not in state.view_instances:
            if route == "/1":
                try:
                    with open(networks_file) as f:
                        networks = json.load(f)
                except FileNotFoundError:
                    networks = {}
                try:
                    with open(networks_stats_file) as f:
                        network_stats = json.load(f)
                except FileNotFoundError:
                    network_stats = {}

                state.view_instances[route] = ViewCls(state, networks, network_stats)
            else:
                state.view_instances[route] = ViewCls(state)
        inst = state.view_instances[route]

        content = inst.render()
        state.view_contents[route] = content

        template.selected_index = int(route[1:]) if len(route) > 1 else 0
        template.content_view = content

        page.views.clear()
        page.views.append(
            ft.View(
                route=route,
                controls=[template.render()]
            )
        )
        page.update()

    page.on_route_change = route_change
    state.route_change = route_change
    page.go(page.route or "/")


if __name__ == "__main__":
    ft.app(target=main, assets_dir="src/assets")
