import flet as ft


def signal_icon(signal):
    # Validate signal is a number
    if not isinstance(signal, (int, float)):
        return ft.Icon(name=ft.Icons.NETWORK_CELL, size=16, color=ft.Colors.GREY_400, tooltip="Invalid")

    # Handle None explicitly
    if signal is None:
        return ft.Icon(name=ft.Icons.NETWORK_CELL, size=16, color=ft.Colors.GREY_500, tooltip="Unknown")

    # Signal strength categories
    if -50 <= signal <= -2:
        return ft.Icon(name=ft.Icons.NETWORK_CELL, size=16, color=ft.Colors.GREEN, tooltip="Excellent")
    elif -70 <= signal < -50:
        return ft.Icon(name=ft.Icons.NETWORK_CELL, size=16, color=ft.Colors.BLUE, tooltip="Fair")
    elif -85 <= signal < -70:
        return ft.Icon(name=ft.Icons.NETWORK_CELL, size=16, color=ft.Colors.ORANGE, tooltip="Weak")
    elif signal < -85:
        return ft.Icon(name=ft.Icons.NETWORK_CELL, size=16, color=ft.Colors.RED, tooltip="Very Weak")

    # Fallback icon if signal is unexpected but valid number
    return ft.Icon(name=ft.Icons.NETWORK_CELL, size=16, color=ft.Colors.GREY_400, tooltip="Unknown")
